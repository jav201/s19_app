# 01 — Requirements · batch-50 (a2l.py lint cleanup + re-freeze)

**BLUF (scope reduced at Phase-2 gate, operator decision 2026-07-19):** Two requirements. `R-A2L-010` (F841) removes the dead `header` local at `a2l.py:942`. `R-A2L-009` (P-2) re-freezes `a2l.py` into the C-27 dual-guard set — as a **guard-files-only post-merge follow-up PR** (a same-PR re-freeze self-trips the vs-`main` guard). **`R-A2L-008` (P-1b) is DEFERRED to a dedicated future batch** — Phase-2 review found it collides with a pre-existing multi-line-header parser limitation (the P-1b logic is correct but fires on nothing in real multi-line A2L until multi-line CHARACTERISTIC/AXIS_DESCR header parsing is added first). Full P-1b analysis + future-batch seed retained in §7 and `02-review.md`. Language: English. RC-1 clean @ `bdebc89`.

---

## 1. Scope & context
- **In scope (batch-50):** delete one dead local in `s19_app/tui/a2l.py`; re-add `a2l.py` to the two frozen-guard test files.
- **Deferred (future batch):** P-1b CURVE/MAP inline-axis length derivation — see §7.
- **Out of scope:** multi-line A2L header parsing (the real P-1b prerequisite); batch-49 `/dev-flow-sync` (independent carry); any DoS byte-cap (rides with the future P-1b batch per operator 2026-07-19).
- **Normative keyword:** `shall` inside HLR/LLR statements only.

## 2.6 Source user stories — Definition of Ready (INVEST)  *(Phase-0 gate approved; Phase-2 rescope applied)*

| ID | User story | Source | Classification |
|----|-----------|--------|----------------|
| US-F841 | As a maintainer, I want the dead `header` local at `a2l.py:942` removed so `ruff --select F841` is clean on `a2l.py`, closing the last lint debt before the module is re-frozen. | Backlog "long-standing carries"; operator 2026-07-19 | **READY** |
| US-P2 | As a maintainer, I want `a2l.py` re-added to the C-27 engine-frozen dual-guard set once its sanctioned edits have landed, so the module returns to read-only-oracle status and future accidental edits are caught at the increment boundary again. | Backlog P-2; operator 2026-07-19 | **READY** (executes as a post-merge follow-up PR-B) |
| US-P1b | As a firmware engineer, I want CURVE/MAP/axis CHARACTERISTICs to show a correct byte length … | Backlog P-1b | **OUT — DEFERRED** (Phase-2: collides with the single-line-header parser limit; needs multi-line-header parsing first. Operator 2026-07-19: defer to a dedicated future batch. Seed in §7.) |

---

## 3. High-level requirements (HLR)

> New ids continue the `R-A2L-*` family (repo-max verified `R-A2L-007`). Both EXTEND/interact with the locked prose at `REQUIREMENTS.md:387-402` — see §6.5.

### HLR-F841 — remove dead `header` local (`R-A2L-010`)
- **Traceability:** US-F841
- **Statement:** The A2L extraction module **shall** not bind the unused local `header` (`a2l.py:942`), and its removal **shall** not change any enriched-tag field for the demo A2L.
- **Rationale (informative):** `header = header_meas or header_char` (`:942`) is never read — the code uses `header_meas`/`header_char` directly (`:975`,`:981`) and passes those into the length-inference calls (`:1055`,`:1058`); the `header` at `:684/701/709/734` is an unrelated function parameter, not this local (architect-confirmed). `ruff --select F841` reports exactly 1 error here (executed 2026-07-19).
- **Validation:** `test` + `inspection` · **Priority:** low
- **Executed verification:** `ruff check --select F841 s19_app/tui/a2l.py`
- **Numeric pass threshold:** `0 errors` (pre-state: 1).
- **Acceptance block:** parsing `ASAP2_Demo_V161.a2l` after the deletion yields byte-identical tag output (proves the removed store was dead). Surface: `parse_a2l_file`. AT: **AT-094** (regression parity + ruff F841=0).

### HLR-P2 — re-freeze `a2l.py` into the C-27 dual-guard set (`R-A2L-009`)
- **Traceability:** US-P2
- **Statement:** After the F841 source edit is merged to `main`, the guard suite **shall** re-include `s19_app/tui/a2l.py` in BOTH frozen sets (`tests/test_engine_unchanged.py::_ENGINE_PATHS` and the `tests/test_tui_directionb.py` tc031 `_ENGINE_PATHS`), the two "UNFROZEN" NOTE blocks **shall** be deleted, and the guards **shall** pass with a zero source diff vs `main`.
- **Rationale (informative):** the a2l-missing-length-fix batch REMOVED (not re-baselined) the C-27 guards, leaving `a2l.py` permanently unfrozen; P-2 restores the dual guard against a post-fix baseline. Only satisfiable **after** merge — a same-PR re-freeze makes `git diff main -- a2l.py` non-empty and self-trips the guard. Executes as **follow-up PR-B (guard-files-only)**.
- **Validation:** `test` + `inspection` · **Priority:** medium
- **Executed verification:** `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031 or tc027 or tc032"` + `git diff main -- s19_app/tui/a2l.py`
- **Numeric pass threshold:** tc031/tc032/`test_tc027` green with `a2l.py` in the frozen set; `git diff main -- s19_app/tui/a2l.py` empty.
- **Acceptance block:** with `a2l.py` back in both `_ENGINE_PATHS`, the frozen-file guards pass because merged source == `main` source. Surface: the guard tests. AT: **AT-095** (guard-green + zero-diff, post-merge). **Sequencing flag:** un-runnable until PR-A merges; PR-B gated on that merge.

---

## 4. Low-level requirements (LLR)

### LLR-F841.1 — delete the dead `header` binding
- **Traceability:** HLR-F841 · **Touched symbol (C-26):** `a2l.py:942`.
- **Statement:** The line `header = header_meas or header_char` (`a2l.py:942`) **shall** be deleted; no other line in the `walk` closure references `header` (verified — only `header_meas`/`header_char` read at `:975`,`:981`,`:1055`,`:1058`).
- **C-26 reverse-census:** `grep -rn "\bheader\b" tests/` over a2l-length tests — existing `tests/test_a2l_record_layout_length.py` calls `_infer_length_characteristic` with a `header` **kwarg** (unrelated to the deleted local); no test asserts on the extraction-walk `header` local. No regression.
- **Validation:** `test` — TC-094 (`ruff check --select F841 s19_app/tui/a2l.py` → 0; demo tags byte-identical, AT-094). Route to a NON-frozen sibling (`tests/test_a2l_record_layout_length.py` or a new `tests/test_a2l_f841_cleanup.py`) — NEVER `tests/test_tui_a2l.py` (tc032-frozen).

### LLR-P2.1 — re-add `a2l.py` to both frozen tuples + delete NOTE blocks
- **Traceability:** HLR-P2 · **Touched symbol (C-26):** `_ENGINE_PATHS` (`test_engine_unchanged.py:120`, `test_tui_directionb.py:5420`).
- **Statement:** In PR-B (post-merge, guard-files only), `"s19_app/tui/a2l.py"` **shall** be re-inserted into `_ENGINE_PATHS` at `test_engine_unchanged.py:120` AND the tc031 `_ENGINE_PATHS` tuple at `test_tui_directionb.py:5420`, and the two "deliberately UNFROZEN" NOTE blocks **shall** be deleted.
- **Validation:** `test` + `inspection` — TC-095. **Threshold:** both guards green; `git diff main -- a2l.py` empty; PR-B touches ONLY the two test files.
- **Sequencing flag:** un-satisfiable pre-merge (same-PR re-freeze self-trips the guard). Encode PR-B as gated on PR-A merge.

### LLR-P2.2 — verify tc032 (`test_tui_a2l.py` freeze) still green
- **Traceability:** HLR-P2 · **Touched symbol (C-26):** `_ENGINE_TEST_FILES` (`test_tui_directionb.py:5435`).
- **Statement:** The tc032 A2L-parser freeze guard **shall** remain green after PR-B, confirming the F841 test landed in a NON-frozen sibling, not `tests/test_tui_a2l.py`.
- **Validation:** `test` — TC-096. **Threshold:** green; no batch-50 test in the frozen file.

---

## 4.9 Canonical AT / TC registry (PINNED — reduced to batch-50 active scope)

**Black-box AT:**
| AT | Story | Asserts | Counterfactual (RED on) |
|----|-------|---------|-------------------------|
| AT-094 | F841 | demo tags byte-identical after delete + `ruff F841==0` | a delete that caught a live line → tag set diverges; ruff still 1 |
| AT-095 | P-2 | frozen guards green + `git diff main -- a2l.py` empty (**post-merge PR-B**) | a2l.py ≠ main → guard RED |

**White-box TC:**
| TC | Backs | Asserts |
|----|-------|---------|
| TC-094 | LLR-F841.1 | ruff F841=0 + demo parity |
| TC-095 | LLR-P2.1 | guards green + empty diff (post-merge) |
| TC-096 | LLR-P2.2 | tc032 green; no batch-50 test in the frozen file |

**Gate-blocking AT:** AT-094 (F841). AT-095 is post-merge (PR-B). *(AT-090..093 / TC-090..093 retired with the P-1b deferral — see §7.)*

## 5.2 Dual traceability (0 gaps, active scope)
- **Behavioral:** US-F841 → AT-094; US-P2 → AT-095 (post-merge).
- **Functional:** LLR-F841.1 → TC-094; LLR-P2.1 → TC-095; LLR-P2.2 → TC-096.
Every active US has an AT; every LLR a TC. No orphans.

## 6.3 Risks / security (active scope)
- **F841:** security-neutral dead-store removal (security-reviewer F6). AT-094's byte-identical-tags assertion is the safety proof.
- **P-2:** re-freeze touches only test-guard lists; the sequencing flag (PR-B off merged main) is the sole failure mode, mitigated by the follow-up-PR structure.
- **C-17 / R1 / R2 / R3:** N/A for batch-50 (all pertained to P-1b's new parsing surface, now deferred). R2 DoS byte-cap rides with the future P-1b batch (operator 2026-07-19).

## 6.5 Requirement amendments (Before → After)
- **Phase-2 descope (operator 2026-07-19):** **Before** — batch-50 = {P-1b, F841, P-2}. **After** — batch-50 = {F841, P-2}; **P-1b DEFERRED** (Deleted from active scope: HLR-P1b/`R-A2L-008`, LLR-P1b.1-4, AT-090..093, TC-090..093). Reason: Phase-2 review (2 blockers) + orchestrator draft-time execution found P-1b unrealizable on real multi-line A2L without multi-line CHARACTERISTIC/AXIS_DESCR header parsing (a core-parser prerequisite, out of "tight cleanup" scope). Reverse edge = requirement-collides-with-reality → operator descope, not iterate-to-fix.
- **REQUIREMENTS.md:387-402** — NO amendment this batch (the CURVE/MAP prose stays as-is; it will be amended when P-1b actually lands).

## 6.4 Reconciliation log
- New req ids: `R-A2L-009` (P-2), `R-A2L-010` (F841). `R-A2L-008` (P-1b) reserved-but-deferred.
- P-2 timing = post-merge follow-up PR-B (guard diffs vs `main`).
- Phase-2 triple review clean on F841 + P-2 (architect: "F841 and P-2 need no change"; security F6 neutral; qa: no F841/P-2 finding). All P-1b findings retired to §7.

---

## 7. DEFERRED — P-1b future-batch seed (retained analysis, NOT batch-50 scope)

Preserved so the future P-1b batch starts from verified ground. Full detail in `02-review.md` §0/§1/§2.

**The real prerequisite (must ship FIRST):** multi-line A2L header parsing. `parse_characteristic_header` (`a2l.py:324-330`) requires all 7 CHARACTERISTIC params on ONE line; the real ASAM demo (`ASAP2_Demo_V161.a2l`) is multi-line → 49/50 CHARACTERISTICs parse `char_type=None`; `axis_meta` (`:1063`, `_find_first_non_empty_line`) captures only the first body line so MaxAxisPoints is unreachable; and `build_section_tree` (`:136-167`) never strips `/* */` comments (a naive flatten yields `header_tokens[3]=="/*"`). P-1 (scalar VALUE) is subject to the same limit (fires only on single-line-header fixtures).

**Then the length logic (design was sound):**
- `record_layout_full_span(layout, axis_counts)` reading `layout["lines"]` (NOT the scalar `_resolve_record_layout`); **the RECORD_LAYOUT `1/2/3` are POSITION INDICES, not counts** — datatype is token[2], token[1] discarded (architect MAJOR-1; naive reader gets 9 not 25).
- `_inline_axis_counts` gated on `_DERIVABLE_AXIS_KINDS={STD_AXIS,FIX_AXIS}`, with live `ALL_AXIS_KINDS`/`_EXTERNAL_AXIS_KINDS` constants + completeness (`ALL == _DERIVABLE|_EXTERNAL`) + non-empty guards (qa M3, C-31).
- Post-axis-walk length pass (R2 ordering); axis_meta build site `:1061-1069` is itself a touched symbol (C-26).
- Safety contract **full-span-or-None** (never under-report). AT-091 (external COM_AXIS stays grey) is the false-green proof.

**Verified oracle values (use these):** STD_AXIS CURVE `ASAM.C.CURVE.STD_AXIS` (`:3321`) = **25 B** (`1 count UBYTE + 8 axis SBYTE + 8 fnc SWORD`); real inline MAP `ASAM.C.MAP.STD_AXIS.STD_AXIS` (`:3539`, axes 4&5) = **51 B** (NOT 146 — 146 is synthetic `[8,8]`). AT authoring: synthetic-single-line-A2L-first (values computable from the string), locate demo tags by NAME not line, name `parse_a2l_file` as the C-12 chain head, add a malformed-input black-box AT (qa M1/M2/M4/M5/M6), correct AT-092 (out-of-image `reason="characteristic address not in S19"`, `validate_a2l_tags:1366`).

**Security:** R2 unbounded `range(byte_size)` (`_extract_raw_bytes:830-844`) — add a `MAX_A2L_DECODE_BYTES` clamp (≈1–16 MiB) when P-1b lands (covers the pre-existing scalar path too). `.get()` not subscript for `DATATYPE_SIZES`; length-guard `header_tokens[3]`.
