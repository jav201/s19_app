# 02 — Phase-2 Cross-Review (qa-reviewer) · batch-37 (US-061/062/063/064a/064b)

> Independent adversarial TESTABILITY review of `01-requirements.md` + `01b-qa-strategy-and-verification.md`.
> Tree: worktree `heuristic-wu-1c7c49` @ `978a900` (RC-1 PASS). Reviewer: qa-reviewer.
> Verdict: **NO BLOCKERS — APPROVABLE.** 2 MAJOR must be folded before the US-062 increment cut
> (Q-01, Q-02); the rest are refinements. All seams, snapshot cells, and the `pilot.click` API were
> re-verified against the live tree (evidence below), not taken on the spec's word.

---

## Findings

| Q-NN | sev | story | summary | evidence | fold |
|---|---|---|---|---|---|
| **Q-01** | **MAJOR** | US-062 | **"page 2 → window index ≥ 512" contradicts the measured-small page size.** The QA strategy (`01b §0/§1`, AT-062b) words the paging AT as "navigate to page 2 → assert a window whose index ≥ the page-1 cap (512)", which silently assumes `page_size == 512`. But `LLR-062.1/062.3` make page size a PILOT-MEASURED body budget, and `LLR-062.3` explicitly says "a small measured page size at 80x24 is acceptable." The entropy body fits ~10–20 jump rows @80x24, and the SAME page slice feeds strip+list, so page size is ~15, not 512 → index ≥ 512 lands on page ~34, not page 2. With prev/next-only controls the AT cannot reach it in one step. | `01b:60-61` (AT-062b "page 2"); `01-req:398-414` LLR-062.1 (same-slice) + `01-req:435-455` LLR-062.3 ("small measured page size … acceptable"); `screens.py:707-717` (`#entropy_body` is `overflow-y:auto`, small height); `test_tui_entropy_viewer.py:345-357` confirms `large_s19` > 512 windows | Reconcile at Phase-2: EITHER add a jump-to-page / last-page control (AT jumps to the last page, asserts a window whose ascending-address index ≥ 512 is present + dismisses with its address) OR have the AT loop `page_next` until the ≥512-index window surfaces (asserting reachability, not a fixed "page 2"). Fix the "page 2" wording in `01b §0/§1`. |
| **Q-02** | **MAJOR** | US-062 | **Two truncation tests break under paging, not one.** Census #3 / §3.2 S8 name "TC-036.5" singular, but there are TWO live nodes: `test_tc036_5_cost_cap_and_truncation` (asserts `#entropy_truncated` PRESENT) and `test_tc036_5_truncation_fires_on_either_cap` (asserts the `min()` either-cap indicator PRESENT). Paging makes the tail reachable → the `TRUNCATED_TEXT` "image exceeds the viewer render cap" indicator is now semantically FALSE; BOTH tests assert its presence and BOTH will fail. Reconciling only "TC-036.5" leaves the either-cap test silently broken. | `test_tui_entropy_viewer.py:345-424` (both fns assert `#entropy_truncated`); `screens.py:651` `TRUNCATED_TEXT`; `screens.py:701-706` `min()` guard; `01b:220` census #3 (singular) | Name BOTH nodes in census #3; redefine the indicator (e.g. `page P/Q` position indicator per `LLR-062.1`) and update both tests' intent+docstrings in the SAME increment. Do NOT blanket-xfail — the strategy already says so; just make it cover both. |
| **Q-03** | MAJOR | US-063 | **Rung-1 `@click`-meta offset→cell resolution on a WRAPPED single `Static` is unproven; rung-2 should be the baseline, not the fallback.** `pilot.click(widget, offset)` exists and returns a bool (verified, textual 8.2.8), but the suite has ZERO prior `pilot.click` and `_strip_text()` WRAPS one `█` per window into the body width (`screens.py:665-667,676-681`), so the wrap column count — hence the offset that lands on cell k — is layout-dependent and genuinely unverified. The spec orders rung-1 (`@click` meta) as primary; that inverts the risk. Rung-2 (per-cell clickable widget → `pilot.click("#entropy_cell_k")`) is deterministic and satisfies C-16 identically. | `Pilot.click` sig verified (textual 8.2.8, returns `bool`); `screens.py:657-681,684` (single wrapping `Static`, no click handler); `01-req:495-518` LLR-063.2 rung order; `01b:101-110` §2.3 (zero prior `pilot.click`) | Make rung-2 (per-cell widget id) the DEFAULT mechanism; only adopt rung-1 if a Phase-3 pilot spike proves the offset→cell hit on the wrapped strip. Either way the AT drives a real Click (C-16 held). Not a blocker — the guaranteed-testable path exists. |
| **Q-04** | minor | US-062/063 | **The existing dismiss handler indexes RAW `self._windows`; it must be remapped under sort+page, and AT-036b is the load-bearing guard.** `on_list_view_selected` does `self._windows[index]` (`screens.py:722-728`). Post-paging/sort the list shows a sorted+paged SLICE, so the row `index` no longer maps to raw `_windows`. `LLR-062.2` pins this. The existing `AT-036b` (`jump.index=1` → expects `0x4000`) stays green only if the remap is correct (2 windows, page 0, address sort → index 1 is still `0x4000`). | `screens.py:722-728`; `test_tui_entropy_viewer.py:139-165` (AT-036b); `01-req:430-433` LLR-062.2 acceptance pin | Use ONE mapping helper `(sort,page,row)→window` shared by BOTH the list-selected path and the US-063 click path (LLR-063.2 already requires "not two divergent index schemes"). AT-036b then doubles as the remap-regression guard — strengthens coverage. |
| **Q-05** | minor | cross-doc | **TC ids diverge between the two Phase-1 docs with no written crosswalk.** `01b §1` uses story-scoped ids (TC-061-1, TC-062-1/2, TC-063-1, TC-064-1/2 = 6) while `01-req §5.2` uses sequential TC-324…TC-330 (7, splitting US-061 reveal-route into TC-330). The header defers reconciliation to the gate but records no explicit mapping → risk of duplicate/misnumbered TCs at Phase-3. | `01b:57-65` §1 vs `01-req:691-693` §5.2 | Add a one-line TC crosswalk (TC-061-1↔TC-330, TC-062-1↔TC-325, TC-062-2↔TC-324, TC-063-1↔TC-326, TC-064-1↔TC-328, TC-064-2↔TC-329) at the Phase-2 fold. |
| **Q-06** | minor | US-061 | **The "persistence" proxy is sound but must state its limit + resolve clear-on-context.** The structural proxy (durable widget survives an unrelated action / re-render) legitimately distinguishes a revealed `.hidden` row from a `notify` Toast, but does NOT prove the control outlives the specific notify TTL. Acceptable + standard; just record it as widget-durability, not wall-clock. The clear-on-context rule (P5 — does a new load / project switch clear a stale offer?) still needs an architect decision. | `01b:268-273` §8.1; `01b:136` P5; `test_tui_patch_editor_v2.py:22-27` TC-052 persistence idiom (F-Q-11) | Record the proxy scope in the AT docstring; resolve P5 (clear-on-context) at the Phase-2 gate. No test-shape change. |
| **Q-07** | minor | US-064b | **MVP scope means "popup shows the CURRENT change-set" is only true for pasted docs.** No `document→JSON` serializer exists (P17), so a FILE-loaded doc leaves `#patch_paste_text` at `DUMMY_CHANGESET_TEXT`; the popup would show the dummy, not the loaded file's JSON. AT-064b's "shows the CURRENT change-set" assertion is therefore only meaningful when the buffer was seeded via paste/parse. Well-flagged in-spec (DF-2) — surfaced here so the AT FIXTURE uses the paste path, not `load`. | `01-req:598-616` LLR-064b.1 acceptance; `01-req:717` P17 (no `to_text`/`serialize`); `app.py:1660-1662` (`parse_paste`→`load_text`, verified) | AT-064b seeds the buffer via the paste/parse seam, THEN opens the popup, edits, confirms, and rereads `service.document.entries` (C-12). Assert "current change-set" against the pasted content, not a `load`ed file. |

---

## Verification log (claims re-checked against the live tree)

| Claim | Probe | Result |
|---|---|---|
| `pilot.click` supports `(widget, offset)` and reports the hit | `inspect.signature(Pilot.click)` | `click(self, widget=None, offset=(0,0), …) -> bool` — offset-click available, returns whether the target was under the pointer ✓ |
| Textual pin | `import textual; __version__` | `8.2.8` (matches the snapshot-regen pin) ✓ |
| Suite has no prior `pilot.click` idiom | read of `test_tui_entropy_viewer.py` | interactions today are `pilot.press` + direct widget calls (`jump.index=1`, `jump.action_select_cursor()`, `test_tui_entropy_viewer.py:157-158`); `asyncio.run(_drive())` wrap (no pytest-asyncio) ✓ — AT-063b introduces the FIRST real click; budget it |
| 4 snapshot cells exist as named | `ls tests/__snapshots__/test_tui_snapshot/` | `test_tc036s_entropy_modal_snapshot[entropy-comfortable-{80x24,120x30}].svg` + `test_tc016s_density_layout_snapshot[patch-comfortable-{80x24,120x30}].svg` ✓ — §4 prediction accurate (2 entropy CERTAIN, 2 patch CONDITIONAL, ≤4 upper bound is per-cell-reasoned) |
| US-064b apply seam | `app.py:1660-1662` | `elif event.action == "parse_paste": result = service.load_text(event.paste_text)` ✓ — the popup-confirm seam exists and is the right one |
| US-061 transient-only affordance today | `app.py:1788-1799` | save-back fires `self.notify("Before/after report ready - press b …", severity="information")` only on `result.ok`; no durable control ✓ (RED real) |
| US-061 single writer | `app.py:1856-1939` `action_before_after_report` | writes `result.md_path`+`result.html_path` via `compose_before_after_report`; refusal → `set_status`, 0 files (`:1937-1939`) ✓ — routing the persistent control here keeps one writer |
| Report-reread idiom exists (C-12 anchor) | `test_tui_report_seam.py` `test_report_seam_writes_real_file_on_disk` | drives the surface → `report.read_text().strip()` off disk, asserts content ✓ — AT-061a's C-12 pattern has a home |
| US-062 sort field present | `screens.py:686,691` | `window.start` / `window.band` / `window.entropy` ✓ — `row 0 .entropy == max(...)` (AT-062a) is realizable |
| Entropy crafted fixture makes AT-062a RED content-real | `test_tui_entropy_viewer.py:45-49` | `_MIXED_MEM_MAP`: window0 `0x3000` H=0.0, window1 `0x4000` H=8.0 → under address sort row0≠max ✓ (RED is content-real, not by-construction) |

---

## Answers to the specific review questions

**1. AT quality (C-10/C-12/C-18).** Strong. Every AT drives a non-default value / asserts CONTENT:
US-062 sort asserts `row0.entropy == max(w.entropy)` with an address-sort negative pairing (a stable
no-op sort cannot pass); US-063 legend asserts the four ACTUAL band→meaning strings coupled to
`ENTROPY_BAND_COLOUR` (anti-drift TC-326, not "a legend exists"); US-061 (C-12) rereads the
handler-written `reports/*.md` off disk; US-064b (C-12) rereads `service.document.entries` after
confirm, never the `TextArea`. Each AT is one on-disk node (C-18 table, `01b §2.4`). No vacuous
pass-conditions found.

**2. Counterfactual soundness.** All 7 REDs are real on the CURRENT tree. Two are content-real
(AT-062a's crafted fixture; AT-063b's `_goto_focus_address` unchanged because the strip posts
nothing); five are by-construction-absent (no control / no legend / no popup) which is legitimate.
The US-063 strip-click concern is about the GREEN side (see Q-03), not the RED — the RED is solid
(plain `Static`, `screens.py:684`).

**3. US-063 strip-click testability.** **Reliably testable — via rung-2, not rung-1.** `pilot.click`
exists and works, but forwarding a Rich `@click` meta AND resolving a click offset to the correct
cell on a WRAPPED single `Static` is unproven in this codebase (Q-03). The reliable, concrete API is
**rung-2**: render each visible-page cell as a per-cell clickable widget with its own id and drive
`await pilot.click("#entropy_cell_k")` — deterministic, no offset math, satisfies C-16. Rung-1
(`await pilot.click("#entropy_strip", offset=(col,row))`) is only viable if a Phase-3 spike confirms
the wrapped-Static offset hit. Recommend rung-2 as the baseline.

**4. Snapshot-drift (C-22).** Verified. The 4 predicted cells exist on disk exactly as named; the
2 entropy cells are CERTAIN drift (modal composition changes), the 2 patch cells are CONDITIONAL
(drift only if US-064a/b add a VISIBLE patch-screen control; the JSON popup is a modal with no matrix
cell). US-061 drifts 0 cells unless it adds a patch-screen child. The ≤4 upper bound is per-cell
reasoned and correct.

**5. US-062 truncation reconciliation.** Handled in-spec (census #3, §3.2 S8) — NOT blanket-xfailed —
but INCOMPLETE: it must cover BOTH truncation tests, not one (Q-02).

**6. US-064b apply seam.** Confirmed correct. `parse_paste → ChangeService.load_text`
(`app.py:1660-1662`) is the exact seam AT-064b assumes; `load_text` is collect-don't-abort
(`change_service.py:640`, `MF-JSON-PARSE`) so the malformed-confirm negative (R7) is satisfiable
without a new error path.

**7. US-061 persistence-as-specced.** Testable via the structural proxy (durable widget survives an
unrelated action), which is legitimate and standard; it does not clock the notify TTL and should say
so, and P5 (clear-on-context) needs an architect decision (Q-06). No blocker.

---

## Overall verdict

**APPROVABLE. No blockers.** Testability is strong across all five stories; the C-10/C-12/C-16/C-18
discipline is genuine (not template-filled), the seams are all confirmed at their cited lines, and
the snapshot prediction is accurate. Two MAJOR items must be folded before/at the US-062 increment
cut:
- **Q-01** — reconcile the "reach index ≥ 512" AT with the measured-small page size (add a
  jump/last-page control or loop `page_next`; fix the "page 2" wording).
- **Q-02** — reconcile BOTH truncation tests, not just "TC-036.5".

Q-03 (make rung-2 the click baseline) is strongly advised but non-blocking (the fallback is
guaranteed-testable). Q-04–Q-07 are refinements resolvable at the Phase-2 fold.

---

## Evidence checklist (qa-reviewer, Phase 2)

- [x] Every requirement's validation method assessed for testability — §"Answers", per-story.
- [x] Each AT checked for C-10 non-default/content assertion — Q-answers §1; no vacuous AT found.
- [x] C-12 output-then-consume verified against a REAL idiom — report-reread `test_tui_report_seam.py` exists; `document.entries` reread confirmed (verification log).
- [x] C-16 real-click feasibility probed on the live tree — `Pilot.click` sig captured; wrapped-Static risk raised (Q-03) with the concrete rung-2 API.
- [x] Counterfactual REDs validated on the CURRENT tree — all 7 real (2 content-real, 5 by-construction); §"Answers" 2.
- [x] Snapshot cells grepped + upper bound re-derived — 4 cells confirmed on disk; per-cell CERTAIN/CONDITIONAL split verified.
- [x] Truncation-vs-paging reconciliation audited — INCOMPLETE (Q-02: two tests, not one).
- [x] Apply seam (`parse_paste`→`load_text`) confirmed at file:line — `app.py:1660-1662` (verification log).
- [x] No real PII / secrets — synthetic `mem_map` + `large_s19` generator + v2 change-set JSON only.
- [x] Test-results sections left BLANK — no execution claimed; only `inspect`/`ls`/`sed`/read recon, outputs quoted.
- [x] Layer B (black-box) present for every output-producing story — report FILE / modal rows / legend Labels + focus address / entries table / `service.document`, all through the shipped surface.
- [x] Bidirectional surface-reachability — inputs (sort key, page nav, real click, external edit, popup edit) AND outputs (report pair, reordered rows, focus address, refreshed table, updated document) exercised through the handler.
- [x] No unfilled template — every finding cites file:line; mechanism-dependent selectors named (rung-2 id / rung-1 offset), TC crosswalk deferred with the mapping written (Q-05).
