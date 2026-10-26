# PDR — architect review — batch 2026-10-26-batch-100

Reviewer: `architect`. Station: PDR (`stations/p3-implementation.md` §PDR).
- **Under review:** `design/design-proposal-b100.md` at `a1cad7e`, against the approved `01-requirements.md` (ledger up to LED .34).
- **Read-only** toward the contract and the proposal. The map (`docs/architecture.md`) and the ARQ record are the architect's own, and were updated as instructed (§3).
- **Nothing committed.**

## Verdict

**`approved with conditions`.** No HIGH and no MAJOR. Five MINOR conditions (ARCH-PDR-1..5), each dischargeable by a named owner at a named increment.

Every requirement is covered. Every SOURCE set is ≤ 4, and the three at-cap reasons hold. The boundaries and the hard order are respected, the enablers are buildable, and there is no fork.

## 1. Findings

| id | severity | location | finding | evidence (executed unless marked) | what closes it (owner · increment) |
|---|---|---|---|---|---|
| ARCH-PDR-1 | MINOR | proposal §5.7 / contract §5.5 Inc 7 ("the plan's `files` row takes its key list from `app.py`"); B100-I17 | Inc 7 stays at 3 files only if `plan_project_save` takes the manifest-key list as an **input from Inc 5 on**. If that parameter is added at Inc 7, Inc 7 touches `project_gather_service.py` and becomes 4. The proposal's §5.5 (Inc 5) does not name the parameter. | LED .34 text; `01-requirements.md:1957`; ARQ §8 Inc 7 | The Inc 5 packet freezes `plan_project_save` with the key-list input. Map row B100-I17 now says so. Owner: Inc 5 implementer; checked at the Inc 5 gate. |
| ARCH-PDR-2 | MINOR | proposal §5.11 ("the preview marks `●` through `choose_install_set` and reads a project's manifest on a cancellable worker"); LED .34 | **Where the dialog gets its data is unstated.**<br>- `choose_install_set` is in `app.py`, and the preview reads `project.json`.<br>- `screens.py` imports neither `app.py` (it would be circular) nor `variant_execution_service.py`.<br>- If the worker lives in the screen, that adds a new view → service edge, which the "no new edge" declaration rules out.<br>The design should say the app supplies the marks and the preview, through a callback or a message. | `grep "^from \.services" s19_app/tui/screens.py` → `operation_service`, `entropy_service`, `report_addendum`, `report_service` only | Inc 9b runs the preview's manifest read on an app-side worker and hands the dialog its rows. The import census at the Inc 9b gate shows no `screens → app` and no `screens → variant_execution_service` edge. Map row B100-I8 now says so. Owner: Inc 9b. |
| ARCH-PDR-3 | MINOR | proposal §5.6, LLR-178.1 mutation column ("a mutation comparing with the first variant by name → the `firmware-patched.s19` arm … (P-39) → RED", written at Inc 6) | **This arm cannot run at Inc 6.** The comparison against the base is `derived_from`, which lands at Inc 7 (B100-I16; the proposal's own §5.6 last bullet). | proposal §5.6 vs §5.7; ARQ §8.1 | Move the P-39 mutation arm of TC-B100-55 to Inc 7. Inc 6 keeps the reason / count / fallback arms. Owner: the Inc 6 and Inc 7 packets. |
| ARCH-PDR-4 | MINOR | proposal §5.14 ("quit asks through the Inc 10 confirm modal, which takes its question text as a parameter, so `screens.py` is not touched"); §5.12 | **Inc 12's file count (2) depends on an Inc 10 design property** that the Inc 10 section does not state. That makes it an unlisted hard-order edge, 10 → 12. | proposal §5.12 (no parameter named) vs §5.14 | The Inc 10 packet builds the confirm modal with its question text and item list as parameters, with a TC arm for a non-load question. ARQ §8 now records 10 → 12. Owner: Inc 10. |
| ARCH-PDR-5 | MINOR | LLR-168.4 / B100-I16 (`derived_from` record) | **The contract names the record's content but not its JSON field names** (the base's name, SHA-256 and byte count). The map uses `base` / `sha256` / `differ` as working names. | `01-requirements.md` LLR-168.4 statement | The Inc 7 packet fixes the field names in the frozen serializer, and the map row follows the packet. Owner: Inc 7. |

## 2. Checks

| Check | Result | Evidence |
|---|---|---|
| ARQ boundaries | ✓ No module is created and no boundary moves. Every file is under `s19_app/tui/**`, and no frozen-engine file is touched. One watch item (ARCH-PDR-2): the preview must not add a view → service edge. | proposal §2; `docs/ARCHITECTURE.md` §10; the `screens.py` import grep |
| SOURCE sets ≤ 4 | ✓ 1:3 · 2:2 · 3:1 · 4:1 · 5:3 · 6:4 · 7:3 · 8a:4 · 8b:3 · 9a:2 · 9b:3 · 10:4 · 11:3 · 12a+12b:2. These equal the contract's §5.5 and the amended ARQ §8. | proposal §5 table; `01-requirements.md` §5.5 |
| At-cap reasons | ✓ for all three increments at 4:<br>- **Inc 6:** a new modal needs `styles.tcss`. Executed: `screens.py:131` documents that modal rules live in `styles.tcss` (the theme tokens resolve only there), and `styles.tcss:1563-1576` holds the shared modal rules.<br>- **Inc 8a:** writer, reader, gather and app each own one side of `active_document`.<br>- **Inc 10:** the dirty flag is private, so the W term needs a public reader. Executed: `screens_directionb.py:4808` `self._dirty`; only `mark_saved` / `mark_loaded` are public, `:5805`, `:5814`. | grep of `screens.py`, `styles.tcss` and `screens_directionb.py` |
| Hard order | ✓ 1 → 6; 2 → 11; 3 → 8a / 10; 5 → 10 → 11; 6 → 7 → 8a; 7 → 9b (`choose_install_set`); 9a → 9b; 9b → 10 (the router route); **10 → 12** (ARCH-PDR-4); 12a and 12b as one unit. The arm moves (ARQ §8.1) match the proposal, except ARCH-PDR-3. | proposal §5.x "Hard order" lines; ARQ §8 / §8.1 |
| Frozen interfaces are in the map with freeze points | ✓ All 22 rows the proposal §4 freezes are in `docs/ARCHITECTURE.md` §11 with the same freeze increment. The map now reflects the PDR-time changes: I1 `derived_from`; I2 `assignments` total cap; I5 fast path only; I8 `choose_install_set`; I9 `%LOCALAPPDATA%`; I14 seam at Inc 7; I15 / I16 / I22 contract forms (ARCH C-1..C-3); I17 key-list input. | §3 below; `git diff -- docs/architecture.md` |
| Foreseen coverage | ✓ 74 of 74 LLRs in §5.15; 72 of 72 TC ids and 21 of 21 AT ids present in the proposal. | `comm` of the `### LLR-` headings vs §5.15 rows: 0 differences; TC and AT id sets equal |
| Enablers buildable | ✓ All files and fixtures exist; the remaining enablers are NEW test support files under `tests/support/`, not SOURCE files.<br>- **Guard files:** `test_import_census.py`, `test_tui_snapshot.py`, `test_id_registry.py`, `test_batch91_registry_hygiene.py`, `test_address_census.py` and `test_engine_unchanged.py` all exist.<br>- **E11:** `tests/support/independent_reader.py` exists.<br>- **E6:** `case_06 firmware.a2l` = 37 742 888 bytes.<br>- **E5:** `LOCALAPPDATA` is set on this host.<br>- **Pins and test lines:** `test_manifest_writer.py:99`, `:216` (`schema_version == 1`) and `:481` (byte-identity) are as cited; `test_tui_app.py:1254`, `:1288` are the two `_handle_load_dialog` tests. | `ls`, `sed -n` |
| Census and token claims | ✓<br>- 15 `copy_into_workarea` call sites in 7 product files (17 grep lines minus 2 docstrings).<br>- P-43: the flag is private.<br>- The `select_variant` binding and the action exist (`app.py:1438`, `:6687`).<br>- The `pa_C` / `pb_A` / `pc_B` / `pe_B` ids were executed at round 2 (P-30). | `git grep`; round-2 records |
| No fork | ✓ One lane, sequential (proposal §8; contract §2.8). | — |
| Forward-applicability | ✓ Every PDR output names its consumer (proposal §7). | — |

## 3. Map and ARQ updates written at PDR (ARCH C-1..C-3 and the rulings)

These are in `docs/architecture.md` and `design/ARQ-batch-100.md`, uncommitted.

| Row | Change |
|---|---|
| B100-I1 | + `derived_from` in the envelope and the verify drift domain (LED .33); freeze "before Inc 7 (`files`, `derived_from`)" |
| B100-I2 | `assignments` capped at 1 000 in total and 1 000 keys (SEC PDR-C2, LED .29) |
| B100-I5 | decided: a fast path into the data comparison only, never deciding copy (LED .32) |
| B100-I8 | `choose_install_set`, a pure module-level function in `app.py`, landed at Inc 7 and reused at 9b (LED .34); the dialog receives marks and preview from the app (ARCH-PDR-2) |
| B100-I9 | `%LOCALAPPDATA%\s19_app\recent_sources.json` (SEC PDR-C3, LED .30); nothing written when unset. R31a amended to match |
| B100-I14 | the manifest seam's `_check_destination_contained` calls `contained_in_workarea` from Inc 7 (SEC PDR-C1, LED .28) |
| B100-I15 | **ARCH C-1:** `rederive_for_save(copy) -> (map, summary)` / `emit_and_verify(map, ranges, …)` |
| B100-I16 | **ARCH C-3:** base name, SHA-256 and byte count computed at the write; panel wording "patched from `<base>` (not in this project); N bytes differ from it"; never "identical" when a record exists; manifest-keys mode, 1 000 cap |
| B100-I17 | the manifest-key list is an input from Inc 5 (ARCH-PDR-1) |
| B100-I22 | **ARCH C-2:** `predict_placement(digest_or_bytes, size, destination, name)`, size first, then digest |
| §10 table | Inc 6 = 4 (at cap, reason), Inc 7 = 3, Inc 9b = 3, Inc 10 = 4 (at cap, `screens_directionb.py`), Inc 12a+12b = 2; the conditional note replaced by "PDR decided every conditional" |
| ARQ §8 | the same counts with ⚠ markers; the 10 → 12 dependency; the banner lists the PDR changes |

## 4. Evidence checklist (architect)

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | Each `executed`: the 4-file cap (§2), the frozen engine untouched, the import edges (the `screens.py` grep), the modal-style convention (`screens.py:131`). |
| 2+ alternatives where a real decision exists | ✓ | ARCH-PDR-2 (app-side worker vs a declared new edge); the proposal §6 records the rest (8 rejected alternatives). Elsewhere `n/a — decided by D1–D7, O-1..O-11, the P2 dispositions and LED .24–.34`. |
| Non-applying constraints marked n/a | ✓ | Network, auth, secrets: `n/a — no external surface`; fork: `n/a — one lane`. |
| Recommendation tied to constraints | ✓ | Each condition names the cap, the edge rule or the hard order it protects. |
| Risks listed | ✓ | §1; proposal §6 (the digest budget is assumed, so it is measured at Inc 11) |
| Cost / latency estimated | ✓ `planned` | The Save-dialog digest budget is 2 s for case_06 (assumed; measured at Inc 11). Hash cost per ARQ §3.1. |
| Diagram when flow is non-trivial | ✓ | proposal §3 (three flows); ARQ §3.4 |
| What would change the recommendation | ✓ | A view → service edge for the preview (ARCH-PDR-2) would need a map declaration. Inc 7 reaching 4 (ARCH-PDR-1) would remove its slack. |
| Two-layer requirements, both chains | ✓ | 74 LLR / 72 TC / 21 AT covered; each AT names its RED |
