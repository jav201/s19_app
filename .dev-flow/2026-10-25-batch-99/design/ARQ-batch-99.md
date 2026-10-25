# ARQ — batch 2026-10-25-batch-99 — read/write integrity

Author role: `architect`. Station: ARQ (`p1-arq.md`). HEAD `307065f`. Status: **for operator approval**; nothing landed.
The standing-map residue is in `docs/ARCHITECTURE.md` §10 *Batch-99 declarations* and §11 *Batch-99 interface amendments* (B99-I1..I9). This file holds the three items the map does not: the `LoadedFile.mem_map` writer census (§2), the parallelisation verdict (§3) and the re-cuts (§4).

## 1. BLUF

- **Boundary:** no module created, no boundary moved. Every touched path is under `s19_app/**` (product) or new under `tests/**`. Three increments cross the frozen engine (§7): Inc 2 and 9 (`core.py`, `hexfile.py`), Inc 10 (`tui/a2l.py`). P1 must name the crossing in those LLRs.
- **Census:** exactly **one** code path writes the bytes of an installed editor image: `apply_change_document` (`tui/changes/apply.py:337`), reached through `ChangeService.apply` (`change_service.py:1657`) from `app.py:3221`. Bytes entries and symbol entries both travel through it as change-document entries. **Re-deriving the image from the source plus the document loses no mutation.** The CRC inject writes a copy; the flow and variant paths write maps they built from the file themselves.
- **Parallelisation:** four file-disjoint lanes exist on paper. **I recommend no fork.** The work runs sequentially in one worktree.
- **Re-cuts:** two path corrections (Inc 6, Inc 11). Two conditional splits: Inc 9 if D6 = refuse, Inc 10 if D4 = flag. One scope question for P1: CRC staging shares the H-3 root.

## 2. Census — every in-place writer of `LoadedFile.mem_map` at HEAD

### 2.1 Method (executed)

```
grep -rnE "mem_map\[[^]]+\]\s*=|mem_map\.update\(|mem_map\.pop\(|del [a-z_.]*mem_map\[|mem_map\.clear\(|mem_map\.setdefault\(|\.mem_map\s*=[^=]|mem_map\s*\|=" s19_app --include=*.py
grep -rnE "\b[a-z_]*(mem|image|memory|bytes_map|working)[a-z_]*\[[^]]+\]\s*=[^=]" s19_app --include=*.py
grep -rnE "\.(update|pop|clear|setdefault)\(" s19_app --include=*.py | grep -iE "mem|image"
grep -rn "apply_change_document(\|inject_crcs\|write_crc_image" s19_app --include=*.py
grep -n "current_file = \|LoadedFile(\|replace(loaded" s19_app/tui/app.py
```

The first two greps return only these subscript writes: `core.py:493`, `hexfile.py:98`, `render/hexview.py:65`, `changes/apply.py:337`, `operations/crc.py:1170`. One rebind is also found: `variant_execution_service.py:766`. The third grep returns no image-map mutation; its 5 hits are widget `.update` calls and a row-list `.pop`.

### 2.2 Result

| # | Site | What it writes | Writes the installed editor image? | Lost if the image is re-derived from the source plus the current document? | US-146 treatment |
|---|---|---|---|---|---|
| W1 | `changes/apply.py:337` in `apply_change_document`, via `ChangeService.apply` (`change_service.py:1657`) ← `app.py:3221` (`apply_doc`; `mem_map = loaded.mem_map`, `:3162`) | the encoded bytes of every `INSIDE` entry. This covers bytes entries and **symbol entries**: `encode_physical_to_raw_bytes` (`change_service.py:540`) fills `entry.encoded_bytes`, and nothing writes the image outside apply | **yes — the only writer** | **no.** These are change-document entries by construction, and the re-derivation re-applies the current ones. Undone and removed entries are dropped, which is the purpose of US-146 | the subject of US-146 (see §2.3) |
| W2 | `changes/apply.py:337` via `flow_execution_service.py:447` (flow PATCH) | the same engine | no. The map comes from the flow SOURCE block, built from the file (`:310-316`) | n/a | none. Each run starts from the file |
| W3 | `changes/apply.py:337` via `variant_execution_service.py:786` | the same engine | no. Each variant map is built from the file (`:759-766`), and `:766` only retains it (`capture_mem_maps`) | n/a | none |
| W4 | `operations/crc.py:1170` in `inject_crcs` | CRC bytes | no. It writes `working_mem = dict(op_input.mem_map)` (`:1151`). Callers: `write_crc_image` `:1326`, the CRC Designer re-render `screens.py:2792`, the flow CRC arm `flow_execution_service.py:650` (flow-local map, reassigned) | n/a | none. **The Patch Editor has no "CRC inject into the editor image" path at HEAD** |
| C1 | `core.py:493`, `render/hexview.py:65`, `hexfile.py:98` | build a new map at load | construction, not mutation | n/a | Inc 2 changes C1–C2 for S0. The source snapshot is taken after that |
| C2 | `app.py:9698` (MAC placeholder map `{addr: 0}`) | a new map for a MAC-only session | construction | n/a | Inc 6 reads `ranges` instead (R21) |
| S1 | `app.py:9894`, `:9946` (`LoadedFile(... mem_map=<existing>.mem_map)`), `replace()` at `app.py:1258`, `:1300` | **share** the same dict across `LoadedFile` instances | no write, but aliasing | n/a | restore **in place** (R20), never rebind |
| L1 | `core.py:402`, `:430` `set_bytes_at` | mutates `SRecord.data` (legacy CLI `patch-hex`, investigation L-7) | no (`S19File`, not `LoadedFile`) | n/a | out of scope |

**Verdict:** re-deriving loses nothing. W1 is the only writer, and everything it writes is a document entry.

### 2.3 Recommended US-146 mechanism (PDR decides; ARQ recommends)

The three real candidates:

| Candidate | Memory | Identity | Files touched | Verdict |
|---|---|---|---|---|
| (a) Full pristine snapshot at load, `image = copy(snapshot) + document` | one more dict entry per image byte. **Estimate, not measured:** roughly 70–100 B per entry in CPython, so about 70–100 MB for a 1 MiB image | a new dict, which breaks the aliases S1 (R20) unless the snapshot is copied back in place | `change_service.py` + `app.py` (the install site) or `models.py` | rejected: memory scales with the image, not with the edit |
| (b) **Original-bytes journal** in `ChangeService`. The first write to an address records its source byte (`_origin: dict[int, int]`). Each apply first restores every journaled address into `mem_map` **in place**, then applies the current document | O(addresses ever patched since load) | preserved | `change_service.py` only | **recommended** |
| (c) Undo / redo / remove also revert the image bytes | O(edit) | preserved | `change_service.py` + every document-mutating method (`:1077`, `:1193`, `:1220`, `:1401`, `:1462`, …) | rejected: every future mutator must remember to revert, and the invariant "image = source + document" never holds by construction |

Rules for (b):

1. **Journal ownership:** bind the journal to the dict object through a held strong reference, compared with `is`. Reset it when that object changes or when `set_image_generation` (`change_service.py:2043`; bumped only at install, `app.py:10827`) pushes a new generation. Do not key on `id(mem_map)`. The service already rejects `id()` because CPython reuses ids (`change_service.py:717`), but a reference the service holds cannot be reused. A MAC attach keeps the dict (S1), so the journal stays valid. A primary unload replaces it, so the journal resets.
2. **Save:** the story's rule is "the image I save equals the source plus the entries currently in my document". That makes *apply → undo → save* (no re-apply) a live case. PDR chooses between:
   - `save_patched` (`:1668`) re-derives before emitting. **ARQ recommends this**, because the rule then holds in any order. Consequence: an entry added after the last apply is written too, and the save status must say so.
   - Save is refused while the document has changed since the last apply.
3. **`before_bytes` meaning changes.** On a repeated apply, `before_bytes` (`apply.py:335`) becomes the **source** byte, not the byte left by the previous apply. Readers: `report_service.py`, `diff_report_service.py`, `flow_report_service.py`, the before/after card. This is the intended meaning, but it changes a recorded value, so P1 must state it in an LLR.
4. **`ranges` need no journal.** Apply writes only `INSIDE` entries (`apply.py:333`), so it never changes `ranges`.

## 3. Parallelisation verdict (mechanical rule, `p1-arq.md`)

All increments are in module **product**, so the six-module intersection is never empty. The rule is applied at file granularity inside product, following the batch-92 precedent (§10). Source-file sets after the §4 corrections:

| Inc | Source files |
|---|---|
| 1 | — (tests only) |
| 2 | `core.py`, `render/hexview.py` |
| 3 | `changes/apply.py`, `workspace.py`, `app.py` |
| 4 | `services/change_service.py` |
| 5 | `operations/crc.py`, `services/flow_execution_service.py` |
| 6 | `segment_split_view.py`, `segment_ops.py` |
| 7 | `app.py` |
| 8 | `flow_execution_service.py`, `flow_report_service.py`, `flow_screens.py` |
| 9 | `core.py`, `hexfile.py` (+ `flow_execution_service.py` if D6 ≠ notice-only; + `app.py` / `load_service.py` if D6 = refuse) |
| 10 | `a2l.py` (+ `change_service.py`, `screens_directionb.py` if D4 = flag) |
| 11 | `change_service.py`, `screens_directionb.py`, `window_help.py` |

**Pairwise matrix** (`·` = disjoint and parallelisable by the rule; `X` = shared file; `c` = shared only under a pending decision; `d` = disjoint files but a dependency on another increment's frozen interface or output):

| | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | – | d | d | d | d | d | d | d | d | d | d |
| **2** | | – | · | · | · | · | · | · | **X** core | · | · |
| **3** | | | – | · | · | d I2 | **X** app | · | c app | · | · |
| **4** | | | | – | · | · | · | · | · | c cs | **X** cs |
| **5** | | | | | – | · | · | **X** fes | c fes | · | · |
| **6** | | | | | | – | · | · | · | · | · |
| **7** | | | | | | | – | · | c app | · | · |
| **8** | | | | | | | | – | c fes | · | · |
| **9** | | | | | | | | | – | · | · |
| **10** | | | | | | | | | | – | c cs/sdb |
| **11** | | | | | | | | | | | – |

Notes:

- **Inc 1 (`d`).** Every RED test of Inc 2, 3, 5, 6 and 9 reads Inc 1's corpus and independent reader, so Inc 1 lands first.
- **Inc 3 → Inc 6 (`d I2`).** If D8 picks replace or dedup, Inc 6 reuses B99-I2.
- **Inc 5 before Inc 8.** Both define `BlockResult` status in one run: Inc 8's roll-up must see Inc 5's CRC `error`.
- **Shared test files that the source sets do not show:**
  - `tests/test_changes_symbol_entries.py` holds both TC-714 (Inc 8) and the encode tests (Inc 10).
  - Inc 2 changes S0-bearing range and byte counts across up to 32 test files that call a map builder (`grep -rln "build_loaded_s19\|get_memory_ranges\|build_mem_map_s19" tests/*.py` → 32). It may also change SVG baselines of hex views of S0-bearing files (109 SVGs under `tests/`; P1 census).

**Lanes that satisfy the rule** (only if D6 = notice-only and D4 ≠ flag): A {2 → 9} · B {3 → 7 → 6} · C {4 → 11 → 10} · D {5 → 8}, with 1 before all. Their file sets are pairwise disjoint.

**Recommendation: do not fork.** The work runs sequentially in one worktree. Reasons:

1. **Little gain.** Every increment has 1–3 source files, so a lane saves little wall time. Each lane adds a merge, a crossed reverse census (C-52 condition 3) and a re-run of the full suite after each merge.
2. **Shared test state.** Inc 1's reader and Inc 2's S0 change move the expected values of the whole suite. A lane that runs the suite before Inc 2 merges is green against stale baselines.
3. **The `pip -e` trap.** Under the editable install, pytest in a git worktree imports the main checkout's `s19_app` unless `PYTHONPATH` points at the worktree. Each lane's evidence would need a `s19_app.__file__` probe, and a missed probe makes the lane's tests vacuous.
4. **Lanes would idle.** Four increments (8, 9, 10, 11) wait on D1–D6, so lanes C and D would stall mid-lane.
5. **B99-I2 must freeze first.** It has to freeze at PDR before Inc 6 consumes it, which serialises lane B internally anyway.

**Proposed order:** 1, 2, 3, 4, 5, 6, 7 (READY), then 8, 9, 10, 11 as D5, D6, D2–D4 and D1 land. These constraints are hard: 1 first; 2 before 9; 3 before 6 and 7; 4 before 11; 5 before 8. If the operator forks anyway, the only cheap split is the engine lane {2, 9} against the rest, conditional on D6 = notice-only.

## 4. Re-cuts and corrections

| # | Increment | Finding | Proposal |
|---|---|---|---|
| RC-1 | Inc 6 | the draft names `tui/segment_ops.py`, but the file is `s19_app/segment_ops.py` | path correction only; 2 source files |
| RC-2 | Inc 11 | the draft omits `tui/window_help.py`, which states the Bytes grammar at `:84`, `:491`, `:510` (text bodies, not the batch-97 I-4 / I-10 key tables) | add it; 3 source files |
| RC-3 | Inc 9 | under D6 = refuse, the policy reaches `flow_execution_service.py` (WRITE-OUT gate) and the load path (`app.py`, `load_service.py`), giving up to 5 files that mix detection and policy | split into **9a** detection (`core.py`, `hexfile.py`) and **9b** policy, which lands after D6. Under D6 = notice-only, 9 stays at 2 files, because SOURCE already surfaces `loaded.errors` (`flow_execution_service.py:357-372`) |
| RC-4 | Inc 10 | under D4 = flag, the flag must reach the picker (`change_service.py`, `screens_directionb.py`) | split into **10a** byte order + RAT_FUNC (H-5, CW-D-10; `a2l.py`) and **10b** COMPU_TAB round-trip + picker surface (H-6). A D3 decode change also moves A2L display tests (`test_a2l_record_layout_walker.py`, `test_tui_a2l_detail.py`) — tests only |
| RC-5 | Inc 3 / Inc 5 | `write_crc_image` stages at `temp/<stem>-crc.s19` (`operations/crc.py:1334`), the same shared-staging root as H-3, but outside US-144's text | P1 decides one of two options: (i) extend US-144 and land the change in **Inc 5**, which already owns `crc.py`, so Inc 3 ∩ Inc 5 stays empty; or (ii) backlog it. Inc 3 must not take `crc.py` |
| RC-6 | Inc 3 | 3 source files, inside the budget. US-144 and PH-3 share one root (staging at `temp/<name>`), so they belong together | no re-cut. The `copy_into_workarea` fix is internal (R19), so its 13 callers are not edited |
| RC-7 | Inc 8 | 3 source files. `flow_model.py` is not needed, because `FlowRunResult` already carries the fields (`flow_model.py:748-758`) | no re-cut. If D5 introduces a new status constant in `flow_model.py`, the count becomes 4, still inside the budget |

### Risks (listed, not mitigated here)

- **S0 ripple (Inc 2).** Range counts, footprints and snapshot baselines of S0-bearing fixtures change. A test that pinned the phantom range will now fail, and P1 must tell those apart from regressions with a census before Inc 2.
- **Placement crash window (Inc 3).** A crash between the exclusive name claim and `os.replace` leaves a 0-byte file under the claimed name. Cleanup on failure belongs in the same `try`. On Windows, `os.replace` onto a file held open by another process raises `PermissionError`; the existing `except OSError` (`apply.py:767`) must turn it into a refusal, not a crash.
- **Recorded value changes (Inc 4).** The meaning of `before_bytes` changes (§2.3 rule 3).
- **Self-referential oracles (Inc 10).** The ASAM MCD-2 MC text is not in the repo, and the audit marks LLR-141.1 as a circular oracle (encode checked against decode). Inc 10's tests must use the corpus manifest (Inc 1) or the example A2L's own stated relation, not a round trip through the code.
- **Index casing.** The map is tracked in the index as `docs/architecture.md` while the working tree has `docs/ARCHITECTURE.md` (`git status` shows ` M docs/architecture.md`). This case mismatch predates the batch, and it is harmless on Windows. A Linux checkout would see a different name than the one cited across the flow.

## 5. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated (state each) | ✓ | 4 source files per increment `executed` (§3 table); frozen engine §7 `executed` (`docs/ARCHITECTURE.md` §7: `core.py`, `hexfile.py`, `tui/a2l.py` listed); public-repo wording `executed` (this file and the map extend only the memory-region extraction vocabulary); cost/latency `n/a — local TUI, no runtime cost`; memory `planned` (§2.3 estimate, not measured) |
| 2+ alternatives where a real decision exists | ✓ | §2.3 (a)/(b)/(c); R19, R20, R21, R23 in the map; R22 states that no real alternative exists |
| Constraints that do not apply marked `n/a` | ✓ | cost/latency, diagram (`n/a — no new edge`) |
| Recommendation tied to constraints | ✓ | §2.3 (memory, identity, file budget); §3 (merge cost, test-state coupling, `pip -e`) |
| Risks listed | ✓ | §4 *Risks* |
| Every touched path under a declared module | ✓ | `git status --short s19_app/ tests/` → empty; all paths exist (`grep -rn "def save_patched_image\|def copy_into_workarea\|def list_projects\|def _load_from_item\|def _handle_save_dialog"` → `apply.py:625`, `workspace.py:262`, `app.py:8314`, `:8816`, `:7940`); `s19_app/segment_ops.py` found by `find s19_app -name segment_ops.py` |
| Boundary verdict with evidence | ✓ | no address change; no new module; candidate edge `segment_split_view → workspace` only (imports at `segment_split_view.py:60-77`) |
| Interfaces + consumers measured | ✓ | §11 B99-I1..I9; e.g. `grep -rn "ChainRunOutcome(" s19_app` → one site, `flow_execution_service.py:1531`; `grep -rn "encode_physical_to_raw_bytes" s19_app` → sole consumer `change_service.py:540` |
| mem_map writer census executed | ✓ | §2.1 commands; product writers = `apply.py:337` (W1–W3), `crc.py:1170` on a copy (`:1151`) |
| What would change the recommendation | ✓ | R18–R23 "re-open" column; §3 (D6 = notice-only, D4 ≠ flag gate the lanes) |
| Diagram when flow is non-trivial | ✓ | `n/a — no new edge; each increment is a local contract change` |
| Two-layer requirements (US→AT→outcome + US→HLR→LLR→TC) | ✗ `planned` | owed at P1. ARQ precedes derivation (`p1-arq.md`), and `01-requirements.md` §3–§4 still hold the template |
