# Review — s19_app — Batch 2026-10-25-batch-99

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer` by trigger family C (always in `full`).

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/review-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

## ✅ Verdict (read first)

- **Gate:** `approve` → PDR, then Phase 3 (round 3, 2026-10-25). Rounds 1 and 2 were `iterate-to-refine`, amended in LED-2026-10-25-batch-99.1 and .2. Round 3: qa `approve`, security `approve`, architect 2 majors (A3-1, A3-2) folded in LED .3 and named `open` until the PDR confirms them against the design proposal.
- **Out-of-scope findings:** 2 named and routed below (S-8 residue, S-9 residue)

- **Findings:** 1 blocker · 20 major · 29 minor (round 1)
- **shall/should check:** ✓ clean (architect: 0 misuse in 49 statements)
- **Two-layer (blockers):** ✓ round 3 — Q-1 closed: US-147 (decode, A2L window, AT-B99-09) and the maintainer story US-152 (encode, codec API, AT-B99-14).
- **Census (change-first):** done — best-effort + gate-confirmed (qa-reviewer, `design/P2-qa.md` §census): TC-714 re-pin certain; S0 shifts range counts in 12+ test files and in snapshot cells over S0-bearing examples; terminator-less test fixtures at risk under HLR-154; `staging_block` arms and `test_manifest_writer` change under HLR-155; golden `tests/goldens/batch71/ac6-unscoped-flow-report.md` drifts under LLR-156.4 (named for Inc 8)
- **Security:** ⚠ 6 major + 5 minor (round 1), all folded in LED .1
- **Evidence checklists (architect / qa / security):** ✓ all complete (in each reviewer file)

---

## Detail (reference)

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| A-1 | architect | major | HLR-153, LLR-153.1/153.2 | C-26: the S0 change touches symbols that no LLR declares. | Add the three symbols and the single predicate (R18) to LLR-153.1/153.2, or add an LLR-153.5 | fixed (LED-2026-10-25-batch-99.1) |
| A-2 | architect | major | HLR-155, LLR-155.1/155.2, US-144 | The staging contract contradicts R19 / B99-I2 and leaves the collision outcome unstated. | Restate LLR-155.1 as R19 does: a per-write directory under `temp/`, with the file keeping its sanitised name | fixed (LED-2026-10-25-batch-99.1) |
| A-3 | architect | major | HLR-155 AT-04, LLR-155.2/155.5, §5.2 | H-3's RED→GREEN is not exercised under D7 = refuse, and §5.2's example contradicts D7. | Make TC-B99-12 and an AT-04 arm drive concurrent writers that request **one** name through a path D7 does not refuse: two chain sets, or a flow plus a save-back | fixed (LED-2026-10-25-batch-99.1) |
| A-4 | architect | major | HLR-157, LLR-157.1/157.2, US-146 | "Applied entries" against "entries currently in my document". | Pick one rule | fixed (LED-2026-10-25-batch-99.1) |
| A-5 | architect | major | HLR-157 (missing LLR) | The change in the meaning of `before_bytes` has no LLR. | Add LLR-157.4: after apply → apply, `before_bytes` equals the source byte | fixed (LED-2026-10-25-batch-99.1) |
| A-6 | architect | major | LLR-157.3 (TC-B99-37) | The census oracle cannot reach its own threshold. | Restate the census as ARQ §2.1 did: list every subscript, `update` or rebind of any name or attribute called `mem_map`, then allow-list the construction site… | fixed (LED-2026-10-25-batch-99.1) |
| A-7 | architect | major | HLR-158, LLR-158.3 (D4) | "The method's tolerance" is undefined, and under `TAB_INTP` it decides almost every outcome. | Define it per kind | fixed (LED-2026-10-25-batch-99.1) |
| A-8 | architect | major | HLR-154/LLR-154.3, HLR-155 D7/D9 (LLR-155.5/155.6); `ARCHITECTURE.md` §11 | Interfaces changed by the requirements but missing from the map. | Declare a stable code per defect in LLR-154.1/154.2 (e.g | fixed (LED-2026-10-25-batch-99.1) |
| A-9 | architect | minor | HLR-156 / LLR-156.1 (D5) | The status bullets overlap | Delete "is blocked" or define it | fixed (LED-2026-10-25-batch-99.1) |
| A-10 | architect | minor | LLR-156.2 | H-10's closure and B99-I3 (`ARCHITECTURE.md:573`, R22) carry `image_ranges` into `ChainRunOutcome` | Add `image_ranges`, or record why it is dropped | fixed (LED-2026-10-25-batch-99.1) |
| A-11 | architect | minor | HLR-162, LLR-162.1–162.3 | Undeclared touched symbols, and a predicate that differs from B99-I9: (a) the Workarea Files list is filled by `refresh_files` (`app.py:6419-6426`, `ListItem(Label(item.name))` with no stored name), which LLR-162.1/162.3 must change but do not name | Name `refresh_files` and the stored-name field | fixed (LED-2026-10-25-batch-99.1) |
| A-12 | architect | minor | LLR-162.3 × LLR-155.1 / LLR-159.3 | LLR-162.3 makes `temp/` user-visible (`refresh_files` lists its files), while LLR-155.1 and LLR-159.3 stage private files in it | Settle this with A-2 (R19 directories), or add "the Workarea Files list shows no staging artefact" | fixed (LED-2026-10-25-batch-99.1) |
| A-13 | architect | minor | IFC Part A | C-54 (`p1-requirements.md:26`): "an LLR claiming a transform with no node is unimplemented" | Add the three nodes (Save project to `image_to_final_file`, the `run_chain_set` start check, and classification in the S0 flow) | fixed (LED-2026-10-25-batch-99.1) |
| A-14 | architect | minor | IFC Part B | The answer "no — the batch changes no component" reframes C-54's question ("does the boundary have independently addressable components? A UI with panels: yes") | Answer yes, and declare COMPONENT blocks for those surfaces with measured consumers (the batch-97 form) | fixed (LED-2026-10-25-batch-99.1) |
| A-15 | architect | minor | LLR-158.2 (D2) | D2 = ASAM is correct (RAT_FUNC is INT = f(PHYS); LINEAR stays PHYS = f(INT)) | State the root pick and the A2L-window rendering of a decode failure, and add an arm with quadratic coefficients | fixed (LED-2026-10-25-batch-99.1) |
| A-16 | architect | minor | HLR-154 / LLR-154.1 (D6) | Under `flujo_para` a false positive stops a flow, yet the controls are only "2 well-formed" files | Make the control set `examples/**/*.s19` → 0 notices | fixed (LED-2026-10-25-batch-99.1) |
| A-17 | architect | minor | LLR-153.3 | The statement says "carry the source's S0 as an `S0` record", but its boundary lists HEX output, where no S0 record exists. | Scope the S0 clause to S19 output, and give HEX output "no data at any undeclared address" | fixed (LED-2026-10-25-batch-99.1) |
| A-18 | architect | minor | LLR-159.3 → HLR-159 → US-148 | The CRC staging clause is the H-3 root (ARQ RC-5 option (i) says "extend US-144, land in Inc 5"), but it is traced to US-148, a story about region coverage. | Trace LLR-159.3 to HLR-155/US-144, keeping its landing in Inc 5, or add the staging outcome to US-148's text | fixed (LED-2026-10-25-batch-99.1) |
| A-19 | architect | minor | HLR-160 / LLR-160.4 (D8) | The recommended `reemplazar` departs from H-9's closure ("stage + dedup like `save_patched_image`") | Show the shared-`splits/` consequence on the decisions page | fixed (LED-2026-10-25-batch-99.1) |
| A-20 | architect | minor | LLR-155.2 | ARQ §4 risks were not carried into requirements: a crash between the name claim and `os.replace` leaves a 0-byte file, and on Windows `os.replace` onto an open target raises `PermissionError`, which must become a refusal, not a crash. | Add both as clauses with a forced-failure TC arm: 0 zero-byte files left, and a status naming the file | fixed (LED-2026-10-25-batch-99.1) |
| A-21 | architect | minor | LLR-157.1 | R20 / B99-I7 require the restore **in place** (same dict object; aliases `app.py:9894`, `:9946`, `replace()` `:1258`/`:1300`) | Add "in place (the same dict object)", and add an arm that observes the reverted bytes through an aliased holder (e.g | fixed (LED-2026-10-25-batch-99.1) |
| A-22 | architect | minor | §6.3 C8 | Markup-safe rendering of file-derived refusal text in lane cells and reports appears only in the informative appendix | Add the clause to LLR-156.2/156.3 (security-reviewer's lens; noted so it is not lost) | fixed (LED-2026-10-25-batch-99.1) |
| Q-1 | qa-reviewer | blocker | US-147 / HLR-158 / AT-B99-09 (LLR-158.1..3 encode limbs) | The AT's driver does not exist at HEAD. | P1 chooses and records one of three options | fixed (LED-2026-10-25-batch-99.1) |
| Q-2 | qa-reviewer | major | HLR-155 / AT-B99-04 | The negative control does not match the AT arm. | Pin the RED claim on the duplicate-name refusal arm and record it as executed for the AT as written | fixed (LED-2026-10-25-batch-99.1) |
| Q-3 | qa-reviewer | major | HLR-159 / AT-B99-10 / US-148 | The oracle contradicts itself. | State whether a CRC `error` stops the flow before WRITE-OUT, then make the statement, the AT, the threshold and US-148 say the same thing | fixed (LED-2026-10-25-batch-99.1) |
| Q-4 | qa-reviewer | major | HLR-153 / AT-B99-02 (also HLR-157's empty boundary) | AT step cannot be driven. | Drive AT-B99-02 with one applied in-image entry, e.g | fixed (LED-2026-10-25-batch-99.1) |
| Q-5 | qa-reviewer | major | LLR-157.3 / TC-B99-37 | The threshold cannot be measured as defined. | Define the predicate | fixed (LED-2026-10-25-batch-99.1) |
| Q-6 | qa-reviewer | major | HLR-158 / LLR-158.3 (provisional D4) | "Within the method's tolerance" is undefined. | Define the tolerance, e.g | fixed (LED-2026-10-25-batch-99.1) |
| Q-7 | qa-reviewer | major | §5.1 / §5.2 regression criterion | The baseline is not this batch's. | Before Inc 1, capture one full-suite baseline at `307065f` into this batch's `evidence/`, and cite its counts and failing node ids | fixed (LED-2026-10-25-batch-99.1) |
| Q-8 | qa-reviewer | minor | HLR-154 shipped surface | Names "Flow Execution run (`#flow_run_*`)" | Name the driver actually used | fixed (LED-2026-10-25-batch-99.1) |
| Q-9 | qa-reviewer | minor | HLR-154 / LLR-154.1 | The HLR names `S5` only, while the LLR adds `S6` | Align S5/S6 between HLR and LLR | fixed (LED-2026-10-25-batch-99.1) |
| Q-10 | qa-reviewer | minor | LLR-162.2 / TC-B99-35 | "Each other home the work area creates" is open-ended, so the threshold "0 reserved homes listed" has no closed set to test | Enumerate the set, or point to one constant tuple that the test imports | fixed (LED-2026-10-25-batch-99.1) |
| Q-11 | qa-reviewer | minor | HLR-162 boundary (empty) | "OK disabled or a notice" leaves the oracle undecided. | Pick one observable | fixed (LED-2026-10-25-batch-99.1) |
| Q-12 | qa-reviewer | minor | HLR-156 status rule | The precedence is open for a document with ≥1 applied entry plus one entry-level ERROR issue, such as `CHG-SYMBOL-UNRESOLVED` on one entry of several | Add the mixed case to the 7-case matrix with its expected status | fixed (LED-2026-10-25-batch-99.1) |
| Q-13 | qa-reviewer | minor | LLR-152.2 | The corpus class "S19 overlap with differing bytes" has no consuming requirement; it loads `ok` with 0 notices today (`rw-p04`) | Name its consumer or mark it oracle-only | fixed (LED-2026-10-25-batch-99.1) |
| Q-14 | qa-reviewer | minor | HLR-155 / LLR-155.2 scope | The statement covers *image* writes | State the scope: images only, or every caller of `copy_into_workarea` | fixed (LED-2026-10-25-batch-99.1) |
| Q-15 | qa-reviewer | minor | LLR-156.4 + golden (C-24) | Not stated: does the flow report render the new not-applied / refusal sections when they are empty (`none`, as LLR-156.3 does for the chain-set report) or omit them? That decides whether `tests/goldens/batch71/ac6-unscoped-flow-report.md` drifts | State it | fixed (LED-2026-10-25-batch-99.1) |
| Q-16 | qa-reviewer | minor | HLR-156 / AT-B99-06/07 | A flow report exists only when the flow carries a REPORT block ("Blocks reported: N (up to the report block)", `rw-p09`) | Name the REPORT block in the AT fixture | fixed (LED-2026-10-25-batch-99.1) |
| Q-17 | qa-reviewer | minor | HLR-155 statement | "It shall never delete a file it did not create" is a universal claim that a single arm checks (same-name save-back). | Narrow it to the writes this batch touches, or add a census arm, e.g | fixed (LED-2026-10-25-batch-99.1) |
| S-1 | security-reviewer | major | HLR-160, LLR-160.1 | The sanitiser grammar is ambiguous and the hostile set is incomplete. | Name ONE grammar: an ASCII allowlist `[A-Za-z0-9_-]` applied to the **segment component** before composing `<stem>_<seg>.<ext>`, never a basename strip | fixed (LED-2026-10-25-batch-99.1) |
| S-2 | security-reviewer | major | LLR-160.2 | Containment is checked against the wrong root, so a junction or symlink destination passes. | Anchor containment to the **work-area root**, reusing the shipped guard: pass both homes through `_check_home_contained` (resolve, `is_relative_to(workarea_r… | fixed (LED-2026-10-25-batch-99.1) |
| S-3 | security-reviewer | major | HLR-160, LLR-160.4 | Sanitising is many-to-one, so with D8 `replace` one export can silently lose a segment. | Compute every final name (sidecars included) at plan time, case-folded | fixed (LED-2026-10-25-batch-99.1) |
| S-4 | security-reviewer | major | HLR-155 vs HLR-160 (D8) | The invariant contradicts the overwrite, and the overwrite is not confirmed. | Scope the HLR-155 invariant explicitly (save-back, flow WRITE-OUT, CRC) and state the D8 exception in HLR-160 | fixed (LED-2026-10-25-batch-99.1) |
| S-5 | security-reviewer | major | LLR-155.2 | `copy_into_workarea` must never move its source. | State in LLR-155.2: `copy_into_workarea` never renames, moves or deletes `source` | fixed (LED-2026-10-25-batch-99.1) |
| S-6 | security-reviewer | major | LLR-155.1, LLR-155.2 | The Windows failure path is not specified. | Add to LLR-155.2: close the reservation handle before the replace | fixed (LED-2026-10-25-batch-99.1) |
| S-7 | security-reviewer | minor | LLR-155.1, §6.3 (H-3) | Staging hygiene. | Give staging files their own prefix (`.stage-<uuid>.tmp`) or a subfolder (`temp/.staging/`) | fixed (LED-2026-10-25-batch-99.1) |
| S-8 | security-reviewer | minor | HLR-156, §6.3 (C8) | The C8 rendering coverage is only partial. | Name `md_safe` / `md_code` for the reports and `markup=False` for notifications in HLR-156 (or §6.3) | fixed (LED .1); the U+202E/U+200B gap in `safe_text` routed to BACKLOG-CODE |
| S-9 | security-reviewer | minor | HLR-154, LLR-154.1, LLR-154.2 | Denial of service in the new loader checks. | Specify: after the first EOF or terminator, count non-empty lines only — no hex parse, no per-line `_add_error`, no image write — and emit **one notice per d… | fixed (LED .1); unbounded line length routed to BACKLOG-CODE |
| S-10 | security-reviewer | minor | LLR-154.1 | The S5 count can overflow, which affects availability. | Compare S5 only when the count is ≤ 0xFFFF and S6 only when it is ≤ 0xFFFFFF | fixed (LED-2026-10-25-batch-99.1) |
| S-11 | security-reviewer | minor | LLR-160.2 | The refusal message carries file-derived text. | Render it with `markup=False` / `safe_text` (the existing export `notify` calls already do this), cap its length, and show the sanitised name next to a clipp… | fixed (LED-2026-10-25-batch-99.1) |

Full text of every finding, with evidence: `design/P2-architect.md`, `design/P2-qa.md`, `design/P2-security.md`.

### shall / should check
Clean — architect checked all 49 HLR/LLR statements at round 1; 0 modal `should`.

### Two-layer acceptance review (blockers)

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-141 / HLR-152 | yes (AT-B99-01) | yes | yes | yes (generator CLI) | ✓ |
| US-142 / HLR-153 | yes (AT-B99-02) | yes | yes | yes after Q-4 fix | ✓ (round 1: driver gap Q-4, fixed) |
| US-143 / HLR-154 | yes (AT-B99-03) | yes | yes | yes | ✓ |
| US-144 / HLR-155 | yes (AT-B99-04, 05) | yes | yes | yes | ✓ (RED arm re-pinned, Q-2) |
| US-145 / HLR-156 | yes (AT-B99-06, 07) | yes | yes | yes | ✓ |
| US-146 / HLR-157 | yes (AT-B99-08) | yes | yes | yes | ✓ |
| US-147 / HLR-158 | yes (AT-B99-09, decode only) | yes | yes | yes for decode; encode TC-only under a recorded exception | ✓ round 2 to confirm (round 1 blocker Q-1) |
| US-148 / HLR-159 | yes (AT-B99-10) | yes | yes | yes | ✓ |
| US-149 / HLR-160 | yes (AT-B99-11) | yes | yes | yes | ✓ |
| US-150 / HLR-161 | yes (AT-B99-12) | yes | yes | yes | ✓ |
| US-151 / HLR-162 | yes (AT-B99-13) | yes | yes | yes | ✓ |

### Supersession census (change-first)
Planned edits: `core.py`, `render/hexview.py`, `changes/apply.py`, `workspace.py`, `app.py`, `change_service.py`, `operations/crc.py`, `flow_execution_service.py`, `flow_report_service.py`, `flow_screens.py`, `segment_split_view.py`, `segment_ops.py`, `a2l.py`, `hexfile.py`, `screens_directionb.py`, `window_help.py`. Families run by qa-reviewer: behavioural placeholder, structural/placement, AST composition (address census `test_address_census.py`), frozen module (§7: `core.py`, `hexfile.py`, `a2l.py` crossings named in their LLRs). Reservations: the full observer list per symbol is re-run at each increment cut (V43, packet `**Reverse census**`). The increment gate confirms completeness.

### Security review summary
security-reviewer round 1 (`design/P2-security.md`): gate input `iterate-to-refine`, 0 blocker, 6 major (S-1 sanitiser grammar, S-2 containment root, S-3 many-to-one names, S-4 overwrite vs invariant, S-5 source never moved, S-6 Windows placement failure), 5 minor. All folded in LED .1. The H-9 approach was judged sound.

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer
Each reviewer's completed checklist (✓/✗ + evidence) is the closing section of its file: `design/P2-architect.md`, `design/P2-qa.md`, `design/P2-security.md`.

### Out-of-scope findings (routed)
| From | What | Owner |
|---|---|---|
| S-8 (c) | `safe_text` strips C0/C1 but not Unicode format characters (U+202E, U+200B) | `BACKLOG-CODE.md` (P2, hygiene) |
| S-9 (residue) | loader line length is unbounded and every parse error stores the whole line (pre-existing, not worsened) | `BACKLOG-CODE.md` (P3) |

---

## Round 2 (2026-10-25) — gate `iterate-to-refine`

- **Round-1 closure:** architect A-1..A-22 22/22 closed; security S-1..S-11 11/11 closed; qa 14/17 closed (Q-1, Q-5, Q-6 open).
- **Round-2 findings:** 1 blocker (Q-1, narrowed to text: US-147 promised an encode the AT cannot observe) · 6 majors (A2-1 = Q-5 census, A2-2 = S-12 BIN/sidecar pair, A2-3 placement return contract, Q-6 `TAB_INTP` arm unbuildable) · 13 minors (A2-4..A2-8, Q-18..Q-22, S-13..S-15).
- **shall/should:** clean (52 statements).
- **Disposition:** every round-2 finding folded in LED-2026-10-25-batch-99.2 (see the ledger for the per-finding change). Round 3 re-reviews the amended clauses.

| ID | Reviewer | Severity | What | Status |
|----|----------|----------|------|--------|
| Q-1 | qa-reviewer | blocker | US-147 promised encoding; AT observes decode only | fixed (LED .2: US-147 → decode, new US-152 maintainer story, AT-B99-14) |
| A2-1 / Q-5 | architect / qa | major | `mem_map` census cannot equal its allow-list | fixed (LED .2: LLR-157.3 and TC-B99-37 retired) |
| Q-6 | qa-reviewer | major | `TAB_INTP` "one beyond refused" arm unbuildable | fixed (LED .2: in-range accepted with a flag; out-of-range refused) |
| A2-2 / S-12 | architect / security | major | BIN and `.addr` sidecar can take different `_<N>`; B8 breaks the threshold | fixed (LED .2: pair claimed together; reuse arm) |
| A2-3 | architect | major | refusal return breaks the `Path` contract of 13 callers | fixed (LED .2: `WorkareaPlacementError` subclass of `WorkareaContainmentError`) |
| A2-4..A2-8, Q-18..Q-22, S-13..S-15 | all | minor | stale map rows, 8-case wording, IFC residue, Part B notice, planning text, real Bytes id, D8 AT arm, census predicate, §6.3, stem cap, `.staging` reparse, record definition | fixed (LED .2) |

---

## Round 3 (2026-10-25) — gate `approve`

- **Closure:** qa Q-1, Q-5, Q-6, Q-18..Q-22 closed; security S-12..S-15 closed; architect A2-1..A2-8 closed.
- **New:** architect A3-1 (major: the BIN/sidecar pair needs a group placement), A3-2 (major: the D4 page text was stale), A3-3 and A3-4 (minor); qa Q-23 and Q-24 (minor); security S-16 and S-17 (minor).
- **Disposition:** all folded in LED-2026-10-25-batch-99.3 (A3-1 → `place_group_into_workarea`, map row B99-I2a; A3-2 → decisions page D4 text). **A3-1 and A3-2 stay `open` with PDR as their owning station:** the PDR's architect and qa confirm them against `design/design-proposal-b99.md`.
- **shall/should:** clean.

| ID | Reviewer | Severity | Status |
|----|----------|----------|--------|
| A3-1 | architect | major | fixed in LED .3 — open, owner PDR |
| A3-2 | architect | major | fixed in LED .3 (page text) — open, owner PDR |
| A3-3, A3-4 | architect | minor | fixed (LED .3) |
| Q-23, Q-24 | qa-reviewer | minor | fixed (LED .3) |
| S-16, S-17 | security-reviewer | minor | fixed (LED .3) |

