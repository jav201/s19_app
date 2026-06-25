# Review — s19_app — Batch 2026-06-25-batch-16 (Phase 2)

**Scope:** US-017 (close batch-11 SCOPE-1 — persist per-variant assignments + batch through the shipped save handler).
**Reviewers (parallel):** architect (F-A-*) ∥ qa-reviewer (F-Q-*) ∥ security-reviewer (F-S-*). Base = `origin/main b734c19`.

## ✅ Verdict (read first)
- **Gate:** PROCEED after light Phase-1 fold (0 blockers).
- **Findings:** 0 blocker · 4 major · 9 minor.
- **Security:** ⚠ MANDATORY sign-off **GRANTED** — 0 HIGH/MED; the new output surface reuses the already-correct `_reject_unsafe_entry` gate (covers both `batch` + `assignments` dict-values, whole-write-refusal), AT-017.4 drives it through the handler. 2 advisory test-strength items.
- **shall/should:** ✓ clean (0 modal-in-statement). **Census:** ✓ all planned files outside frozen; `manifest_writer.py`/`variant_execution_service.py` confirmed read-only substrate.

## Majors (4)
| ID | Theme | Finding | Disposition |
|---|---|---|---|
| **C1 = F-A-01 + F-Q-02** | **D-KEY incomplete (stem collision)** | `variant_id` = filename stem ONLY when stems don't collide; on collision (`fw.s19`+`fw.hex`) every colliding id becomes the FULL FILENAME (`workspace.py:399-403`). Spec's flat "stem" → UI that recomputes `Path.stem` will mis-key colliding variants → silent consumer drop (`:599/602`). AT-017.2's single-variant fixture wouldn't catch it. | Restate D-KEY: keys = the variant's actual `VariantDescriptor.variant_id` (stem, OR full filename on collision); LLR-017.3/.4 forbid UI recomputing `Path.stem`; **add a stem-collision AT** (`fw.s19`+`fw.hex` → assignment round-trips + picked up). |
| **C2 = F-Q-01** | AT-017.4 counterfactual vacuous | The collective "all RED pre-fix because on-disk empty" is wrong for the NEGATIVE AT-017.4: pre-fix the handler ignores assignments, so no escaping entry exists → AT passes for the wrong reason (vacuous). | AT-017.4 asserts a POSITIVE refusal observable (surfaced refusal notice/status from the handler when an escaping assignment is supplied) — impossible pre-fix; state pre-fix failure mode PER AT. |
| **C3 = F-Q-03** | D-KEY trap needs exact-tuple | Under `scope="all"` a mis-keyed assignment silently drops the per-variant file but the variant stays in the plan; AT-017.2 catches it ONLY if it asserts the EXACT tuple `batch + assignments[vid]`, not "non-empty". §5.2 row says only "plan tuple". | Tighten AT-017.2 / §5.2 row to exact-tuple equality (LLR-017.4 threshold already says this — propagate to the AT prose). |
| **C4 = F-A-02** | Service-path citations | All `manifest_writer.py`/`variant_execution_service.py` citations omit the `tui/services/` prefix; bare paths don't exist → breaks the census reasoning at face value. | Prefix all citations with `tui/services/`. |

## Minors (9)
| ID | Finding | Disposition |
|---|---|---|
| F-A-03 | `_handle_save_dialog` def is `app.py:3552` (spec implies 3644 = the call site). | Cite def `:3552` + call `:3644`. |
| F-A-04 | `SaveProjectPayload` construction is a single line `screens.py:188` (not 183-188). | Fix anchor. `frozen=True` → `field(default_factory)` guidance is correct. |
| F-A-05 | `plan_variant_executions` real sig has `fallback_batch=()`; `scope="all"` must equal `SCOPE_ALL` constant. | Reconcile literal vs constant at Phase 3. |
| F-A-06 | Duplicate section number `6.5` (increment decomp + amendments). | Renumber amendments → §6.7. |
| F-Q-04 | `_write_and_verify_manifest` gains a NEW param (`*, batch, assignments`) — flag `NEW — created in Phase 3` + name it. | Add to LLR-017.2. |
| F-Q-05 | LLR-017.1 "byte-identical" zero-selection claim vs AT-017.3 "empty maps" mismatch (always-serialize `batch:[]`/`assignments:{}` is NOT byte-identical to today's keyless file). | Narrow LLR-017.1 to "re-reads identically / semantically equivalent" (reader tolerates absent keys). |
| F-Q-06 | LLR-017.3 pilot TCs (TC-304/305/306) need a pre-existing multi-variant `_variant_set` set up BEFORE `action_save_project` (D-NEWPROJ timing) or the screen has no rows to render. | Add the precondition to LLR-017.3 executed-verification. |
| F-S-02 (adv) | AT-017.4 should assert `project.json` NOT written at all on refusal (whole-write-fail), not merely "0 escaping entries". | Strengthen AT-017.4 (file-absence/unchanged-mtime). |
| F-S-04 (adv) | Add a TC: an in-project symlink pointing outside is refused (the resolve-then-containment chain already fails closed). | Add to AT-017.4 sibling set. |

## Orchestrator recommendation
**iterate-light** — fold C1–C4 + the 9 minors into the LLR/AC bodies (body-first; §6.6 audit rows), re-confirm, proceed to Phase 3. All are the reviewers' own prescriptions — no design change, no HLR/LLR statement re-derivation. The increment plan is unchanged (Inc 1 payload+threading+ATs; Inc 2 UI); C1's collision AT lands in Inc 1, the UI key-sourcing rule binds Inc 2.
