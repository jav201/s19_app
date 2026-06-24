# Increment 1 — Emitter width + S0-capture data layer (US-015)

**Batch:** 2026-06-23-batch-14 · **Branch:** claude/batch-14-us015 (off origin/main 9169130) · **Status:** awaiting gate · **Not committed.**
**LLRs:** LLR-015.1 (bytes_per_line), LLR-015.2 (s0_header, emitter-side), LLR-015.4 (reader-as-oracle + neg control), partial capture seam for LLR-015.2. **Inc2 = save-flow wiring + UI (deferred).**

## 1. What changed
Data-layer mechanism only (no save-flow/UI): `emit_s19_from_mem_map` gained `bytes_per_line: int = 32` ({16,32}, validated at entry before any record — F-S-03) and `s0_header: bytes|None=None` (populated S0 if given, **bounded len≤252** — C4/F-S-02, else ValueError; empty S0 when None). `LoadedFile.source_s0_header` added (additive). `build_loaded_s19` captures the first S0 record's data (read-only on the frozen reader). Emitter docstring/doctest corrected (F-A-04).

## 2. Files modified (4 source/test + 1 spec; ≤5)
- `s19_app/tui/changes/io.py`, `s19_app/tui/models.py`, `s19_app/tui/services/load_service.py`, `tests/test_changes_apply.py`, `.dev-flow/2026-06-23-batch-14/01-requirements.md` (§6.5 amendments).

## 3. How to test
`pytest tests/test_changes_apply.py -q` · `pytest --doctest-modules s19_app/tui/changes/io.py -q` · `pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031" -q` · `ruff check <changed>`.

## 4. Test results
ruff clean; `test_changes_apply.py` 38 passed (24 base + 14 new); doctest 4 passed/2 skipped; engine-frozen guard 7 passed (0 diffs); full non-slow suite **863 passed / 0 failed**. Ledger: **903 → 916 (+13)**. Coverage-claim: all 14 named TC functions verified on disk (TC-212..218, TC-226, C4 overflow, F-Q-05, S0-capture).

## 5. Risks / amendments
- **§6.5b Amendment B (premise correction, RATIFY):** spec claimed "populated S0 adds 0 addresses to mem_map" — FALSE. `core.py:485 get_memory_map` folds *every* record's data (no type filter), so a populated S0 at addr 0 adds keys 0..N-1. **Independently verified by orchestrator + code-reviewer.** Mitigation: assert S0 inertness against a DATA-record-only map (S0@0 never collides with high-address firmware; and even under deliberate overlap the data record, written after S0, overwrites it — code-reviewer probed this). Integrity property HLR-015 needs (data records round-trip byte-equal) is preserved. Binds Inc2: AT-015.1/AT-015.2 oracles use the data-record map.
- **§6.5a Amendment A:** C4 S0 ≤252 bound is a NEW acceptance threshold on LLR-015.2 (Before/After recorded).

## 6. Pending
Inc2 (save-flow wiring + {16,32} selector UI) applying C1 (S19-branch-only dispatch), C2 (CRC→32 + A-5 row), C3 (selector pilot AT), F-A-05 (two-hop threading), using the Amendment-B data-record-map oracle.

## 7. Independent review
code-reviewer: **APPROVE** (0 HIGH / 0 MED / 2 LOW nits). Amendment B verified correct + safe to ratify = YES. No security surface (no secrets/external I/O/new write target) — Inc1 correctly scoped to the data layer; the new write-content reaches disk only via Inc2's save flows (already-secured path).

## Gate
0 HIGH findings; awaiting operator approval to commit Inc1 + advance to Inc2. **Ratification asked:** Amendment B (data-record-map oracle premise).
