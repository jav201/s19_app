# 02 — Cross-agent review — 2026-07-11-batch-37

> BLUF: **1 blocker + 3 majors → iterate-to-refine** (autonomous fold). Security **PASS** (0 HIGH/MEDIUM,
> 4 LOW folds). All findings are corrections/gates — no story killed. Every cited seam re-verified TRUE
> (incl. the DF-2 no-serializer claim and the C-16 real-click AT). Sub-reviews:
> `02-review-{architect,qa,security}.md`.

## Consolidated findings (severity-ordered)

| id | sev | story | summary | evidence | fold |
|----|-----|-------|---------|----------|------|
| **A-01** | **blocker** | US-064b | File-loaded data-loss footgun: popup seeds from `#patch_paste_text` which still holds DUMMY after a file load (load only refreshes the table); Confirm silently `load_text`-REPLACES the loaded doc → data loss. AT-064b boundary "no-op re-parse" is factually false in this state. | `app.py:1652-1659`; `change_service.py:667-668` | **Disable "Edit JSON" when `document.source_path is not None`** + add a file-loaded boundary AT asserting the popup is blocked (no clobber). MVP stays paste-only. |
| **A-02 / Q-01** | major | US-062 | Page-size model self-contradictory: LLR says page size = small pilot-measured body budget; ATs assume 512/page. ~15-row body → index ≥512 lands on page ~34, unreachable by one next. | `01-req:398-455`; `screens.py:707-717` | **Pin page size = 512** (the existing cap becomes the per-page window budget, FIXED — not pilot-measured; the jump list scrolls in the modal body). Pilot-measure governs only the control/legend geometry. Fix "page 2" wording (page 2 = windows 512–1023). AT-062b valid under this pin. |
| **Q-02** | major | US-062 | TWO truncation tests break under paging, not one: `test_tc036_5_cost_cap_and_truncation` AND `test_tc036_5_truncation_fires_on_either_cap` both assert `#entropy_truncated`. | `test_tui_entropy_viewer.py:345-424` | Name BOTH nodes in the census; redefine the indicator to `page P/Q` semantics; update both in the US-062 increment. |
| **Q-03 / A-05** | major | US-063 | C-16 rung-1 `@click`-meta offset→cell on a wrapped single `Static` is unproven (0 prior `pilot.click`). | `screens.py:657-681` | **Make rung-2 (per-cell clickable widget) the BASELINE**, not fallback (deterministic, satisfies C-16). AT: `pilot.click("#entropy_cell_k")`. Rung-1 offset becomes an optional Phase-3 spike. |
| **Q-04** | minor | US-062/063 | `on_list_view_selected` indexes raw `_windows` — must remap under sort+page. | `screens.py:722-728` | Remap select→window under the sort+page index; AT-036b is the load-bearing regression guard. |
| **A-03** | minor | US-064a | Refresh source contradiction (widget path-input vs `document.source_path`). | LLR vs QA TC | Pin **`document.source_path`** (survives a post-load path-input edit). |
| **A-04 / Q-06** | minor | US-061 | HLR "until the editing context changes" clause has no owning LLR/AT; persistence proxy doesn't clock the notify TTL. | HLR-061; QA P5 | Give the clear-on-context an owning LLR + AT arm, or soften to informative; state the proxy doesn't clock TTL. |
| **Q-05** | minor | cross-doc | TC ids diverge (01b `TC-061-1…` vs 01-req `TC-324…330`), no crosswalk. | — | Reconcile to **TC-324…330** (drop the 01b local ids). |
| **Q-07** | minor | US-064b | MVP "shows CURRENT change-set" only holds for pasted docs (no serializer). | P17 | AT-064b fixture seeds via **paste**, not `load`. |
| **S-01** | low | US-064b | New `#changeset_json_text` TextArea must route paste through the existing 65 KiB clipboard funnel, not a 2nd uncapped ingress. | `os_clipboard_input.py:72` | Route paste through the funnel. |
| **S-03** | low | US-063 | Mirror the `0 <= index < len` bound in `action_jump`; hold the no-`[`/`]` legend pin (TC-326). | `screens.py:722-728` | Bound + markup pin. |
| **S-02 / S-04** | low | US-064a / US-061 | Refresh inherits existing (no-regression) TOCTOU/symlink; persistent control is a 2nd trigger onto the single writer (no new write surface). | `io.py:398`; `app.py:1856` | No action beyond noting no-regression. |

## Security verdict
**PASS — 0 HIGH/MEDIUM.** US-064a refresh reuses the validated `ChangeService.load` (size-capped, no bypass); US-064b popup routes through `parse_paste`→`load_text`→`json.loads` (no `eval`/`pickle`, no new write surface). No new external-write surface. Engine-frozen untouched.

## Re-verified TRUE (architect)
DF-2 no-serializer claim (no `to_text`/`serialize` in `change_service.py`); C-16 real-`pilot.click` AT; all cited seams accurate; `shall`/`should` contract holds; both traceability chains complete.

## Gate disposition
1 blocker (A-01) + 3 majors → **iterate-to-refine** (autonomous): fold all findings into `01-requirements.md`
(§6.5 Before/After), re-reconcile TC ids + the AT registry (C-21), re-verify, then self-approve Phase 2.
No story killed.
