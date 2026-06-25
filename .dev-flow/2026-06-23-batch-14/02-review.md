# Review — s19_app — Batch 2026-06-23-batch-14 (Phase 2)

**Scope:** US-015 only (16/32 S19 record width + populated S0 header). US-016/HLR-016/LLR-016.*/AT-016.* SATISFIED by batch-15 (main §20) — not reviewed.
**Reviewers (parallel):** architect (F-A-*) ∥ qa-reviewer (F-Q-*) ∥ security-reviewer (F-S-*). Base = `origin/main 9169130`.

## ✅ Verdict (read first)
- **Gate:** PROCEED after light Phase-1 fold (0 blockers).
- **Findings:** 0 blocker · 4 major · 9 minor · 3 security clearances.
- **shall/should check:** ✓ clean (0 modal misuse in statements).
- **Census (change-first):** done — best-effort + gate-confirmed; all 8 planned files outside both frozen guard lists.
- **Security:** ⚠ 1 major (F-S-02 S0 length bound) + clearances; sign-off **ADVISORY** (no new write surface — content-only change through secured `copy_into_workarea`).
- **Evidence checklists (architect / qa / security):** ✓ all complete.

## Findings register

### Majors (4)
| ID | Theme | Finding | Disposition |
|---|---|---|---|
| **C1 = F-A-01#1 + F-Q-01** | Polymorphic emit dispatch | `save_patched_image` calls `emit(mem_map, ranges)` via `_SAVE_BACK_EMITTERS` (`apply.py:99/687`) — shared by S19 AND `emit_intel_hex_from_mem_map` (`io.py:1533`, rejects the new kwargs). Passing `bytes_per_line`/`s0_header` blindly → `TypeError` on HEX save-back. | LLR-015.3: new kwargs **S19-branch-only** (branch on `source_kind=="s19"` before `emit(...)`); HEX branch untouched. **+TC**: `save_patched_image(source_kind="hex", bytes_per_line=32)` proves HEX unaffected. |
| **C2 = F-A-01#2 + F-Q-02** | Third S19 save surface (CRC) | `crc.py:879` `write_crc_injected_image` calls `emit_s19_from_mem_map(...)` directly → inherits the new **32** default silently; absent from scope/A-5 matrix. | **Accept CRC→32** (uniform output; D2 re-parse-equal; architect verified no CRC test asserts row width). Add §1.2 note + A-5 matrix row for `crc.py:879`. No pin-to-16. |
| **C3 = F-Q-03** | AT not at shipped UI surface | AT-015.1/.3 realized only by service-level TC-219/220/213/217 (`save_patched_image`), not a Pilot through the NEW {16,32} selector. A wired-but-unread selector passes all TCs (US-016's TC-224 shows the right `run_test` pattern). | Add a **pilot-level realizing node for AT-015.1**: `run_test` → selector=32 → save → read on-disk `.s19` → assert >16/≤32-byte S3 records + non-empty S0. |
| **C4 = F-S-02** | S0 length overflow | S0 payload unbounded; `_s19_record` renders `byte_count` as `{:02X}` single byte (`io.py:1511/1519`). `len(s0_header) > 252` → byte_count > 255 → malformed record. | LLR-015.2: **bound `len(s0_header) ≤ 252`** (truncate-with-`ValidationIssue` or `ValueError`); **+TC** an over-long S0 is not emitted as a broken record. |

### Minors (9)
| ID | Finding | Disposition |
|---|---|---|
| F-A-02 | `test_engine_unchanged.py:120-127` freezes **6** paths (no `color_policy.py`); 7th lives only in `test_tui_directionb.py:3738-3746`. Spec cites the 7-set to the wrong guard. | Correct §2.4/§6.4 citation (two guard lists, differ by `color_policy.py`). |
| F-A-03 | `SaveBackDecision` class is `screens_directionb.py:477`; spec cites `:707` (decline post-site). | Re-point to `:477`. |
| F-A-04 | Emitter docstring/doctest (`io.py:1431-1447,1460` "16 data bytes max") goes stale on the flip. | Add docstring update to Inc1 DoD. |
| F-A-05 | D1 threading crosses TWO service hops: `change_service.save_patched` (`:860`) + `save_patched_image` (`:574`) + `variant_execution_service.py:711`. Inc2 = exactly 5 files, zero slack. | Make two-hop threading explicit in LLR-015.3; note Inc2 budget tight. |
| F-Q-04 | `LLR-015.x` (TC-221 engine guard) placeholder id; `-k engine_unchanged` matches no test (real: `test_tc031_*` / TC-027). | Assign real id **LLR-015.5** + statement; pin `-k`/nodes (provisional V-5). |
| F-Q-05 | AT-015.2 "HEX emitter unmodified" claim has no guard (`io.py` outside frozen set). | Add 1-line inspection (diff `HEX_DATA_BYTES_PER_RECORD`+`emit_intel_hex_from_mem_map` vs main = 0) OR soften claim (TC-226 proves behaviorally). |
| F-Q-06 | TC-218 negative control corruption unspecified — corrupting inert S0 passes vacuously. | Pin TC-218 to flip a **data-record** byte. |
| F-Q-07 | V-5: confirm TC-212..218/226 land in `test_changes_apply.py` (not new `test_changes_io.py`). | Add to §6.6 owed-list. |
| F-S-03 | `bytes_per_line` validated at function entry **before** any row emitted. | LLR-015.1 confirm validate-before-emit at Inc1 gate. |

### Security clearances (no action)
- **F-S-01** write reuses secured `copy_into_workarea` (`workspace.py:215`) — no new target/clobber/traversal.
- **F-S-04** S0 inert + filename-derived — no secret/info-leak (subject to C4).
- **F-S-05** engine-frozen untouched; S0 capture READS `core.py::S19File.records` only.

## Orchestrator recommendation
**iterate-light** — fold C1–C4 + the 9 minors into LLR/AC bodies (body-first), record §6.6 audit rows, re-confirm, proceed to Phase 3. Dispositions are the reviewers' own prescriptions; no HLR/LLR statement re-derivation, no design change. Increment plan unchanged (Inc1 + Inc2): C1/C2/C3 fixes land within existing files; C3 adds one pilot TC in Inc2's test file; C4 adds a bound + TC in Inc1.
