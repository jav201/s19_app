# PLAN.md — batch-20 (living compendium)

> **D-1 + D-2 declared-region cleanup bundle** — closes batch-19's declared-region line.
> Updated at every gate + significant checkpoint. The operator reads THIS, not state.json.

## Where we are
- **Phase 6 — Documentation.** `awaiting-gate`. 06-docs (matrix/functionality/diagrams/exec-summary) written; REQUIREMENTS.md §26 added; BACKLOG refreshed (D-1/D-2 DONE). Next: operator approval → commit/PR/sync.
- Phase 5 — Post-mortem `approved` (inline-paste protocol formalized + encoded).
- Phase 4 — Validation `approved` (PASS, 942 passed/0 fail).
- Phase 3 — Implementation `approved` (A+B+C; 958→974 +16).
- Phase 2 — Cross-review `approved` (0 blockers; 6 folds; 3 Phase-3 carries).
- Phase 1 — Requirements `approved` (HLR-027/028/029, 9 AT + 7 TC).
- Phase 0 — DoR `approved` (both READY; capture = On Generate).

## Phase-3 carries (from cross-review)
- **C-P3a:** port `_notices()` from `test_tui_manifest_save.py:64-78` into `test_tui_report_seam.py` (install before Generate press) so AT-029a-d observe `self.notify`.
- **C-P3b:** keep D-2 notify **count-only** (no offending-line interpolation — toast renders pre-scrub).
- **C-P3c:** thread `declared_regions` into `write_project_manifest` only, NOT `verify_written_manifest` (re-reads file as oracle).

## Surface map (disk-verified, Phase-0 spike)
- **Shipped/reuse (no change):** `write_project_manifest`/`serialize_manifest` (`manifest_writer.py:386/:225`, emit key only when non-empty), `read_project_manifest`→`ProjectManifest.declared_regions` (`variant_execution_service.py:201,539`), `DeclaredRegion` scrub at `__post_init__` (`report_addendum.py:72`).
- **D-1 SAVE seams:** `ReportViewerScreen.__init__` (`screens.py:658`, no regions param) + `compose`/TextArea seed (`:683`, empty); `SaveProjectPayload` (`screens.py:81`, no field); `_handle_save_dialog`→`_write_and_verify_manifest` (`app.py:3770/:3778`, no regions threaded); new `self._declared_regions` app state.
- **D-1 LOAD seams:** `_handle_load_project` (`app.py:3934`, reads manifest, ignores regions); `action_view_reports` push (`app.py:1860`, no regions passed).
- **D-2 seams:** `_parse_declared_regions` (`screens.py:543-578`, silent skip logs `:571/:577`); `on_button_pressed` (`screens.py:770-789`) → `set_status`/`notify` idiom (`app.py:7756` / `:3842`). Callers: handler + `test_tui_report_seam.py:350`.

## Objective
Wire the declared-region persistence shipped in batch-19 (serialization layer only) to the actual UI, and stop silently dropping mistyped region lines.
- **D-1 (UI save/load wiring, HLR-026 follow-on):** (a) PROJECT-SAVE persists the report dialog's declared regions into `project.json`; (b) PROJECT-LOAD pre-fills the `ReportViewerScreen` region TextArea from `ProjectManifest.declared_regions`.
- **D-2 (skipped-line feedback):** surface a COUNT of skipped blank/malformed/invalid region lines to the operator (notify/set_status) instead of `logger.info`-only.

## RC-1 base-currency gate (run at open) — PASS
- `git fetch origin` → `origin/main` tip = **818a02b** (PR #31 batch-19 merged).
- branch HEAD == merge-base(HEAD, origin/main) == **818a02b** → current, clean working tree.
- Per-story already-shipped grep on `origin/main`: **both net-new** — only the report-GENERATE path + serialization layer exist; no project-save persistence wiring, no load pre-fill, no skipped-line count.

## Stories (DoR pending)
| ID | Story | INVEST risk | Status |
|----|-------|-------------|--------|
| D-1 | Declared regions survive project save/load through the UI | needs app-level region state (net-new); two sub-surfaces (save, load) | intake |
| D-2 | Operator sees a count of skipped region lines | tiny; reuse existing notify idiom | intake |

## Roadmap / increment plan (Phase-1 finalized)
- **Inc A — HLR-027 SAVE** (`app.py`, 1 file): `self._declared_regions` state + capture on `GenerateRequested` + thread through `_write_and_verify_manifest` → existing serializer. ATs: AT-027a/b/c. TCs: TC-027.1/.2/.3.
- **Inc B — HLR-028 LOAD** (`app.py` + `screens.py`, 2 files): capture from manifest in `_handle_load_project` + pass to `ReportViewerScreen` + seed TextArea (inverse of parser). ATs: AT-028a (GATE, C-12) / AT-028b (guard). TCs: TC-028.1/.2.
- **Inc C — HLR-029 D-2** (`screens.py` + `tests/test_tui_report_seam.py`, 2 files): `_parse_declared_regions` returns `(regions, skipped)` + `self.notify` count; updates batch-19 TC-024.5 (return-shape). ATs: AT-029a/b/c/d. TCs: TC-029.1/.2.
- Dependency order: A → B (needs A's state attr) → C (independent, last).

## Key decisions
- Scope = D-1 + D-2 bundle (operator, Phase 0). #8/#12 deferred.
- /dev-flow full rigor (operator-invoked).

## Risks / watch-items
- **App-level declared-region state does not exist yet** — D-1 likely needs a new `S19TuiApp` attribute as the single source of truth shared between the report dialog (writes) and the save path (reads) and the load path (seeds). Confirm via Explore.
- **C-13 geometry:** D-1/D-2 add no new always-on widgets to a constrained row (the report TextArea already exists), so geometry risk is low — confirm no new persistent affordance is added at 80/120 cols.
- **Security (batch-19 lesson):** region NAME already scrubbed at `DeclaredRegion.__post_init__` + read-path. D-1 round-trips the same scrubbed data; re-confirm no NEW unscrubbed external-write surface is introduced (save path writes name to project.json — already covered by the serializer + scrub, verify).
- Worktree-not-operator-editor-root: paste artifacts inline at each gate.

## Conventions honored
- Engine-frozen set OFF-LIMITS. ≤5 files/increment. Two-layer AT/TC + dual traceability. Commits/PRs only on approval.

## Out-of-scope carries
- #8 patch-editor overhaul (P1), #12 before/after+entropy+reconcile (P2) — remain in BACKLOG.

## Test ledger (collected non-slow)
- Base (origin/main 818a02b): **958** (985 total, 21 slow deselected, 6 going to 964 — see below).
- **Inc A: 958 → 964 (+6)** — AT-027a/b/c + TC-027.1/.2/.3. 0 fail.
- **Inc B: 964 → 968 (+4)** — AT-028a/b + TC-028.1/.2. 0 fail. D-1 round-trip complete.
- **Inc C: 968 → 974 (+6)** — AT-029a/b/c/d + TC-029.1/.2; TC-024.5 rewritten in place (net 0). 0 fail.
- **Phase-3 total: 958 → 974 (+16)** across 3 increments. Frozen diff 0 throughout.
- **Phase-4 confirmed: 942 passed / 29 skip / 3 xfail / 0 FAIL (974 collected).** Reconciles.
- (batch-19 close cited 926 in different units; 932 *passed* this run = 964 collected − 29 skipped − 3 xfailed. Reconciled.)

## Decision log (human mirror of state.json)
- 2026-06-29 P0: batch-20 initialized, D-1+D-2 scope, RC-1 PASS, surfaces net-new.
