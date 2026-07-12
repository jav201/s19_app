# 02 — Phase-2 Cross-Review (architect) · batch-37

> Independent, adversarial review of `01-requirements.md` (§2.6/§3/§4/§5/§6) +
> `01b-qa-strategy-and-verification.md`. Reviewer did NOT author these requirements.
> Every cited seam RE-VERIFIED against the worktree tree (not trusted from the ledger).
> Verdict at bottom. Base tree `978a900`.

## Verdict: **BLOCKERS PRESENT → iterate** (1 blocker, 2 major, 2 minor)

The spec is structurally strong: 5 US → 5 HLR → 14 LLR, both traceability chains complete,
every US carries a first-class black-box AT, geometry is honestly DEFERRED to Phase-3
pilot-measure (not fr-estimated), and the supersession census is thorough. The `shall`/`should`
contract holds. **Two of the three claims I was asked to re-verify are TRUE** (the DF-2
no-serializer claim; the C-16 real-click AT). But the DF-2 paste-buffer MVP hides a reachable
**silent data-loss footgun** the acceptance layer not only fails to guard but actively
mis-describes, and the US-062 page-size model is internally contradictory. Both must be
reconciled before Phase-3.

---

## Re-verification of the three flagged claims

| Claim | Spec says | Re-verified | Result |
|---|---|---|---|
| **DF-2 no serializer** | `ChangeService` has only `load`/`load_text`, no `document→JSON` (`to_text`/`serialize`), so the popup must seed from the paste buffer (P17) | `grep 'def (to_text\|serialize\|as_text\|to_json\|dumps\|to_dict\|export)'` in `change_service.py` → **0 matches**; only hit is a comment "never serialized by" (`change_service.py:907`) | **TRUE** — no serializer exists |
| **C-16 real click** | AT-063b drives a REAL `pilot.click` on `#entropy_strip`, never a proxy call to `action_jump`; rung-1 = Rich `@click` meta on a `Static`, rung-2 = per-cell widgets | `screens.py:684` strip IS a plain `Static`; `screens.py:722-728` jump idiom `dismiss(self._windows[index].start)` confirmed; AT-063b (§3, L221-241) drives `pilot.click` + asserts the exact dismissed address | **TRUE** — genuinely black-box; but see A-05 (mechanism unprecedented in-repo) |
| **US-064b applies via `load_text`** | popup Confirm routes through the existing `parse_paste`→`load_text` seam (`app.py:1660-1662`) | `app.py:1660-1662` confirmed (`parse_paste` → `service.load_text(event.paste_text)`); `load_text` REPLACES `self.document` (`change_service.py:667-668`) | **TRUE** — but the replace-semantics is what makes A-01 dangerous |

---

## Findings

| A-NN | sev | story | summary | evidence (file:line) | fold |
|------|-----|-------|---------|----------------------|------|
| A-01 | **blocker** | US-064b | **File-loaded footgun.** The popup seeds from `#patch_paste_text`, but after a `load_doc` file load the paste box still holds `DUMMY_CHANGESET_TEXT` (never updated on file load — only the entries table refreshes). So: load a change FILE → open the JSON popup → it shows stale DUMMY text (NOT "the current change-set" the story/AT promise) → **Confirm silently `load_text`-REPLACES the loaded document with the DUMMY-derived changeset = data loss.** AT-064b's own boundary "confirm with no edit is a no-op re-parse, not a crash" is **factually FALSE** in this reachable state (it is a destructive replace, since buffer ≠ document). The spec acknowledges the serializer gap (DF-2, LLR-064b.1) but closes it only in prose — no disable-guard, no boundary AT for the file-loaded case. | seed: `01-req.md:598-616`, `screens_directionb.py:1977` (`TextArea(DUMMY_CHANGESET_TEXT)`); file load leaves buffer stale: `app.py:1652-1659` (load_doc sets `service.document`, never touches `#patch_paste_text`); destructive replace: `change_service.py:667-668`; false boundary claim: `01-req.md:287-288` | Phase-2 |
| A-02 | major | US-062 | **Page-size model is self-contradictory.** LLR-062.1/062.3 define page size as the *small* C-23 pilot-measured cell/row budget ("page size ≥ 1 at 80x24", "small measured page size at 80x24 is acceptable"). But AT-062a's observable + boundary assume page size = **512**: "navigate to a page beyond the first ... index ≥ 512" and "exactly 512 windows → single page, no pager" (QA S5 same). If page size is the measured ~20-40, then 512 windows span ~15-25 pages — "single page" is false and "index≥512 on page 2" is false. The two readings cannot both hold. | LLR-062.1 `01-req.md:398-414` ("page size shall be the C-23 pilot-measured cell/row budget"); LLR-062.3 `01-req.md:455`; AT-062a boundary `01-req.md:158-180`; QA S5 `01b:148` | Phase-2 |
| A-03 | minor | US-064a | **Refresh source-of-truth contradiction between the two Phase-1 artifacts.** LLR-064a.1 refreshes from the `#patch_doc_path_input`/`#patch_doc_file_select` widget value; QA TC-064-1 refreshes from `ChangeService.load(document.source_path)`. These diverge if the operator edits the path input after loading (widget-value refresh then loads a *different* file — that's "load", not "refresh"). The "re-read THAT file to reflect external edits" intent points to `document.source_path` (which exists, `model.py:250`). Pin one. | LLR-064a.1 `01-req.md:549-557`; QA TC-064-1 `01b:64`; `source_path` field `model.py:250,453` | Phase-2 |
| A-04 | minor | US-061 | **Normative "until the editing context changes" clause is untested and unimplemented.** HLR-061 asserts (`shall`) the control "remains queryable and actionable until the operator acts or **the editing context changes**", but no LLR pins what a context change is or how the stale control clears, and AT-061a does not exercise it. QA P5 explicitly flagged this clear-on-context rule "for the architect at Phase-1" — Phase-1 (requirements) did not resolve it. Either drop the clause or add an owning LLR + boundary. | HLR-061 statement `01-req.md:302-305`; AT-061a boundary catalog `01-req.md:151-156` (no context-change leg); QA P5 flag `01b:136,272-273` | Phase-2 |
| A-05 | minor | US-063 | **C-16 rung-1 mechanism has zero precedent in this codebase.** `grep '@click\|meta=\|Style(meta'` across `s19_app/` → the only hit is an unrelated `mac_meta=` kwarg (`app.py:7397`). The Rich `@click`-meta-on-a-`Static` action-link mechanism (rung 1) is real in Textual in principle, but it is unproven here AND the suite has zero prior `pilot.click` idiom (QA §2.3). The spec correctly flags this `assumed — pilot-verify in Phase 3` with a guaranteed-testable rung-2 (bounded per-cell widgets). No change required, but rung-1 verification is load-bearing — fund rung-2 as the real plan, not a footnote. | grep result (`@click`/`meta=`: 0 action-link hits, only `app.py:7397 mac_meta=`); LLR-063.2 rungs `01-req.md:495-518`; QA §2.3 `01b:101-110` | Phase-3 |

---

## What is SOUND (adversarial confirmation)

- **Traceability (both chains):** §5.1 behavioral US→AT→outcome and §5.2 functional US→HLR→LLR→TC are both complete. 5 US → 5 HLR → 14 LLR; every HLR → exactly one US; every LLR → its parent HLR; every US ≥1 black-box AT. No orphan, no dangling HLR/LLR.
- **Normative keyword contract:** `should` appears only in the contract statement (`:94`) and the evidence-checklist prose (`:765`) — never inside an HLR/LLR `shall` statement. No modal-`should` blocker.
- **C-23 geometry correctly DEFERRED:** LLR-061.3 / 062.3 / 063.3 / 064b.3 all require reading the real `content_region` at 80x24 AND 120x30; every envelope number is flagged `assumed — pilot-measure in Phase 3`. The batch-36 F-01 "fr-math was ~4.5× off" lesson is cited. US-061's "persistence + queryability + activation, NOT above-the-fold" acceptance is the correct call for the height-starved 5-row panel (F-01); the rung-2 durable-status-line fallback is sound.
- **AT genuineness:** all 7 ATs are black-box through the shipped surface (real save-back+click+file-reread; real sort/page control + jump-row read; real `pilot.click`; external file edit + real refresh; popup open + real Confirm + document reread). None is a proxy/setter call. C-10 content assertions throughout (max-entropy row, exact clicked address, second-version-only entry).
- **Supersession census (change-first) is complete** and matches the code: truncation `#entropy_truncated`/TC-036.5 RE-EXAMINE (census #3) is correctly named — `screens.py:703-706` `min(caps)` indicator confirmed; the `on_list_view_selected` raw-index→window mapping that sort+paging breaks is pinned as a correctness obligation (LLR-062.2 acceptance, `screens.py:722-728` verified indexes raw `self._windows[index]`); before/after goldens C-24 SURVIVE (composer `before_after_service.py:183` untouched); patch snapshot cells CONDITIONAL-drift; `PATCH_ACTIONS_V2` count supersede-if-11th-action. No engine-frozen module is touched (`screens.py`, `screens_directionb.py`, `app.py`, services all non-frozen; `ENTROPY_BAND_COLOUR` is in non-frozen `screens.py:569`).
- **Increment cut / C-21:** the Inc-1..5 cut is sound; the one hard ordering dep (US-062 before US-063, so the click-to-window mapping builds on the settled sort+page index) is correctly identified (§6.6). Every AT has an owning increment; registry (7 ATs / 7 TCs) reconciled before any Phase-3 cut.
- **Reveal idiom reuse (US-061)** is real: `show_save_prompt`/`hide_save_prompt` toggle `.hidden` on `#patch_saveback_row` (`screens_directionb.py:2280-2310`) — a like-for-like host for `#patch_before_after_row`. Notify seam (`app.py:1794-1799`), `result.ok` gate, and decline path (`app.py:1762`) all verified accurate.

---

## Evidence checklist (architect Phase-2)

- ✓ **Constraints stated** — each story's scope boundary carried into HLR/LLR; re-verified against §2.6.
- ✓ **≥2 alternatives / rungs considered** — C-16 rung-1/rung-2; US-064b MVP-vs-serializer; US-061 button-vs-status-line fallback.
- ✓ **Recommendation tied to constraints** — verdict + per-finding remediation tied to the shipped surface + the F-01 geometry constraint.
- ✓ **Risks listed** — A-01 data loss, A-02 model ambiguity, A-03 seam divergence, A-05 unprecedented mechanism; operational/correctness classes covered.
- ✓ **Cost/latency** — N/A (presentation-only TUI batch, no model calls / new I/O cost); compute snapshot unchanged (`compute_entropy` called once, `screens.py:655`).
- ✗ **Diagram** — not warranted (no new cross-component flow; all changes are in-surface extensions).
- ✓ **What would change the recommendation** — A-01 downgrades to non-blocker IF a disable-guard (`document.source_path is not None` → Edit-JSON disabled) + a file-loaded boundary AT are added; A-02 resolves once page-size is pinned to ONE definition.
- ✓ **Two-layer requirements** — every US has a first-class Acceptance block + AT-NNN; both traceability chains exist (§5.1 + §5.2). Confirmed complete.

---

## FINAL RETURN — for the orchestrator

**Findings**
- `A-01 | blocker | US-064b | file-loaded footgun: popup seeds stale DUMMY_CHANGESET_TEXT after a file load and Confirm silently load_text-REPLACES the loaded document (data loss); AT-064b's "no-op re-parse" boundary is false in this reachable state; no disable-guard/boundary AT | 01-req.md:598-616,287-288 · screens_directionb.py:1977 · app.py:1652-1659 · change_service.py:667-668`
- `A-02 | major | US-062 | page-size model contradictory: LLR-062.1/062.3 = small measured budget vs AT-062a/QA-S5 = 512-per-page ("exactly 512 → single page", "index≥512 on page 2"); pin one | 01-req.md:398-414,455,158-180 · 01b:148`
- `A-03 | minor | US-064a | refresh source contradiction: LLR-064a.1 uses widget path-input value, QA TC-064-1 uses document.source_path; diverge if path input edited post-load; pin document.source_path | 01-req.md:549-557 · 01b:64 · model.py:250`
- `A-04 | minor | US-061 | HLR-061 normative "until the editing context changes" clause has no owning LLR and no AT; QA P5 clear-on-context flagged for Phase-1, unresolved | 01-req.md:302-305,151-156 · 01b:136`
- `A-05 | minor | US-063 | C-16 rung-1 @click-meta mechanism has ZERO in-repo precedent (grep: only unrelated mac_meta=); correctly flagged assumed + rung-2 fallback; keep rung-2 funded | app.py:7397 · 01-req.md:495-518`

**Overall verdict:** BLOCKERS → **iterate**. One blocker (A-01) + one major (A-02) must be resolved in the Phase-2 fold; A-03/A-04/A-05 are cheap pins. No structural/traceability defect — the two-layer requirements and both chains are complete.

**Spec claims re-verified:**
- DF-2 "no `document→JSON` serializer on `ChangeService`" — **TRUE** (`change_service.py`: no `to_text`/`serialize`/`to_json` def; only a "never serialized by" comment at `:907`). But the paste-buffer MVP it justifies is unsafe as specced → A-01.
- C-16 "AT-063b drives a REAL click, not a proxy" — **TRUE** (`pilot.click` on `#entropy_strip`, asserts exact dismissed address; strip is a plain `Static` `screens.py:684`, jump idiom `screens.py:722-728`). Rung-1 forwarding mechanism is unproven in-repo (A-05) but the AT and rung-2 fallback are sound.
- No other cited seam was FALSE on re-verification (notify `app.py:1794-1799`, save-back `:1713`/`:1762`, load/parse dispatch `:1652-1662`, reveal idiom `screens_directionb.py:2280-2310`, paste box `:1977`, entropy caps `screens.py:585-586`, `source_path` `model.py:250` — all accurate).
