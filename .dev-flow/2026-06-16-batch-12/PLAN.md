# Batch-12 — CRC_F2 — Living Plan & Compendium

> **What this is:** the single navigable index for batch-12. Updated at every gate. The phase artifacts (`01-requirements.md`, `02-review.md`, `03-increments/`) are the detail; this is the map. **BLUF at the top of every section.**

---

## 0. Where we are RIGHT NOW

**Phase 5 (Post-mortem) — COMPLETE, AWAITING YOUR GATE.**
- ✅ Phases 0-4 done & committed (Phase 4 = 272b4a7). ✅ Phase 5: [`05-postmortem.md`](05-postmortem.md) co-authored (architect process + qa-reviewer test-strategy retrospective).
- **Headline:** closed clean with one in-flight re-scope (J-3); the A-4 census stress-test HELD under a real adversary, the KAT anchor caught a real bug, and the A-5 surface-reachability control prevented a SCOPE-1 recurrence. 0 code defects.
- **2 new controls proposed:** (a) extend the symbol-citation rule to **consumer input contracts** (would have caught J-3 at Phase 1); (b) Phase-1 **facade/test blast-radius** budgeting. **7 next-batch items** (A-3 save-flow carry, RK-3 device vector, CLI `ops`, CI trigger gap, codify reader-as-oracle, …).
- ⏳ Phase 5 needs your `approve` → **Phase 6 (documentation)** — the last phase before close.

---

## 1. The goal (one paragraph)

Add a **CRC32 operation** to s19tool: compute a CRC32 over configured memory regions of an S19/S3 firmware and either **check** it against the value already stored (non-mutating, the default) or, on operator confirmation, **inject** it and emit a modified S19 — surfaced in the s19_app report. CRC params (poly/init/reverse/xorout/ranges/addresses) live in an **external config** so real per-firmware values never enter the repo.

**Two user stories:**
- **US-011 — Check:** compute + compare vs the stored 4-byte LE value per output address, file untouched.
- **US-012 — Inject + emit:** write the CRC (4-byte LE, extending the image if it lands in a gap), emit a modified S19, verify it, operator-confirmed.

**Your locked Phase-0/2 decisions:** reverse = refin/refout (zlib); params OPEN via external JSON config (+ TUI text view with dummy values); stored value = 4-byte **little-endian** fixed; write-into-gap = **extend** mem_map+ranges; surface = **TUI-only**; CRC result lands in **BOTH** the operations-result view AND the persistent report.

---

## 2. The roadmap — 6 increments (each ≤5 files)

| # | Increment | Scope | LLRs | Status |
|---|-----------|-------|------|--------|
| **I1a** | Neutral contract | `OperationInput` + `from_loaded`; `execute` retyped off `LoadedFile` (both call-sites migrated atomically); `OperationResult` +`crc_regions` | LLR-005.1/.2 | ✅ **committed** (dd665b0) |
| **I1b** | CRC engine (headless) | Parameterized CRC32 + region assembly + 4-byte LE codec; `REQ-crc.md`; engine tests | LLR-001.1/.2/.3, LLR-005.3 | ✅ **committed** |
| **I2** | Config + check (headless) | dummy JSON template, config reader (resolve+size-cap+collect), read-stored-4LE + compare → `CrcRegionResult[]` | LLR-004.1, LLR-002.1/.2 | ✅ **reviewed CLEAN, awaiting gate** |
| **I3a** | Operation wiring | `CrcOperation` REAL in `crc.py` (consume `check_regions` → `OperationResult{status=ok, crc_regions}`); `config` via execute kwarg; placeholder removed + facade rewired | LLR-002.2 (assembly) | ✅ **reviewed CLEAN, awaiting gate** (7 files, ≤5 exception) |
| **I3b** | TUI surface | config TextArea (dummy pre-fill) + per-region rows + worker-thread (R-6); F-L1 honored; stale-worker race fixed | LLR-004.2, LLR-002.3/.4 | ✅ **committed** (4312dcd) |
| ~~**I4**~~ | ~~Persistent report~~ | **WITHDRAWN (§6.4 J-3):** `report_service` is project/variant-scoped; CRC is per-file. The CRC persistent record = the operation's emitted S19 + `OperationResult` (folded into I5). | ~~LLR-002.5/003.5~~ | ❌ **withdrawn** |
| **I5a** | Inject + emit + verify (headless) | 4-byte LE inject (extend on gap, sorted/merged) + `emit_s19_from_mem_map` into the contained work area (`copy_into_workarea` seam) + reader-as-oracle verify + `CrcWriteResult` carrier | LLR-003.1/.2/.3 + re-scoped LLR-003.5 (record) | ✅ **reviewed (code OK + security CLEAN), awaiting gate** |
| **I5b** | TUI confirm + write surface | two-stage operator confirmation (R-6) + write worker (token-guarded) + assemble `OperationResult` + render write outcome (F-L1: verified/mismatch/failed) | LLR-003.4 + LLR-003.5 (surface) | ✅ **reviewed (1 MEDIUM fixed), awaiting gate — LAST** |

**Dependency order:** I1a → I1b → I2 → I3a → I3b → I5a → I5b (I4 withdrawn). **7 increments.** No increment depends on a later one. (I5 split into I5a/I5b at the I5 kickoff — headless write mechanics then the confirm surface.)

---

## 3. Requirements at a glance (5 HLR / 18 LLR)

Full text: [`01-requirements.md`](01-requirements.md).

- **HLR-001** — CRC32 compute engine (headless, parameterized, segment-chained). *[I1b — done]*
- **HLR-002** — Region check: read stored 4-LE, compare, report (non-mutating) → both surfaces. *[I2–I4]*
- **HLR-003** — Inject + emit modified S19 + verify, operator-confirmed. *[I5 + I4]*
- **HLR-004** — Config sourcing (external JSON) + TUI text surface. *[I2–I3]*
- **HLR-005** — Neutral input contract + `OperationResult` widening (resolves the batch-08 deferred C-7/R-2/R-3). *[I1a — done]*

**The load-bearing acceptance anchor:** `crc32(b"123456789", default) == 0xCBF43926` (TC-101) — proves the engine is genuinely CRC-32, not just self-consistent. A green suite without it does not pass the bar.

---

## 4. Key design decisions (D-1..D-8, condensed)

| ID | Decision |
|----|----------|
| D-1 | `OperationInput` neutral input (mem_map+ranges+metadata); `from_loaded` adapter is the only `LoadedFile` coupling. |
| D-2 | `OperationResult` +`crc_regions` (optional, default None) + `CrcRegionResult{output_address, computed_crc, stored_value, matched, written}`; `STATUS_DOMAIN` unchanged; `output` = input snapshot (check) / injected map (inject). |
| D-3 | `CrcConfig`/`CrcRegion` from external JSON; dummy `examples/crc_config.example.json` carries fake values only. |
| D-4 | Default = zlib/PKZIP CRC-32 (poly 0x04C11DB7, init/xorout 0xFFFFFFFF, refin/refout); all four params config-driven. |
| D-5 | Stored/written CRC = 4 bytes little-endian, FIXED (not parameterized). |
| D-6 | Write-into-gap: work on a copy, extend mem_map + (sorted, merged) ranges. |
| D-7 | `REQ-crc.md` co-located with the operations module (C-7); app docs reference it. |
| D-8 | R-6 side-effect controls: worker-thread + per-execution confirmation + contained output path (`copy_into_workarea`/`is_relative_to`). |

---

## 5. Risks (RK-1..6, live)

- **RK-1** — Contract decoupling deeper than expected → SPIKE fallback (re-aimed at the run_operation+test rewire). *Mitigated: I1a landed clean.*
- **RK-3** — Non-zlib device CRC correctness needs an operator reference vector → "assumed, verify Phase 3/4". *TC-106b now pins 2 published variant KATs; a bespoke device convention is still the residual.*
- **RK-5** — Config-path / output-path safety → write contained via `copy_into_workarea`; config read uncontained-by-design + size-capped; security-reviewer sign-off mandatory at I5.
- RK-2 (app/screens structural surface), RK-4 (endianness fixed 4-LE), RK-6 (range merge ordering) — all mitigated in-spec.

---

## 6. Verification ledger

| Checkpoint | Collected | Lean pass | Notes |
|-----------|-----------|-----------|-------|
| Batch-11 close (baseline) | 839 | 786 | re-measured (V-7) |
| After I1a | 841 | 788 | +2 (TC-108/109) |
| After I1b | 850 | 797 | +9 (TC-101..107, TC-106b, no-mutation) |
| After I2 | 860 | 807 | +10 (6 config + 4 check); review CLEAN |
| After I3a | 862 | 809 | +2 (execute no-config / with-config); review CLEAN |
| After I3b | 871 | 818 | +9 (5 parse + 3 pilot + 1 race regression); 1 MEDIUM fixed |
| After I5a | 877 | 824 | +6 (inject/emit/verify/no-write/result/containment); security CLEAN, F-S-06 folded |
| After I5b | 879 | 826 | +2 (TC-124 confirm-gate / TC-125 through-handler); 1 MEDIUM F1 fixed. **Phase 3 done.** |
| Phase 4 full suite | 879 | **847 full** | `pytest -q` (incl. slow): 847 passed / 0 failed / 29 skipped / 3 xfailed; signed-balance 879 = 839 + 40 (EXACT) |

- Frozen-engine guards: **green** at every step (CRC lives in new files; `range_index`/`core` reuse import-only). A-4 census stress-test: **CLEAR**.
- KAT TC-101: **green**.

---

## 7. Decision log (gates)

| Date | Phase | Decision |
|------|-------|----------|
| 2026-06-16 | batch-11 close | re-synced to vault, snapshot, closed |
| 2026-06-16 | 0 | both US READY, both surfaces, 6-increment plan — **approved** |
| 2026-06-16 | 1 | 5 HLR / 18 LLR — **approved** |
| 2026-06-16 | 2 | 0 blockers / 8 majors / 11 minors → **iterated** → all closed → **re-confirmed approved** |
| 2026-06-16 | 3 / I1a | implemented, reviewed (0 HIGH), **approved + committed** |
| 2026-06-16 | 3 / I1b | implemented, reviewed (1 HIGH fixed), **approved + committed** (d7e862e) |
| 2026-06-16 | 3 / I2 | config + check (headless), reviewed CLEAN, **approved + committed** (ae73288) |
| 2026-06-16 | 3 / I3a | CrcOperation real (Path A, 7 files), reviewed CLEAN, **approved + committed** (7658d4e) |
| 2026-06-16 | 3 / I3b | TUI surface (config editor + worker + rows), reviewed (1 MEDIUM race fixed, 0 HIGH), **approved + committed** (4312dcd) |
| 2026-06-16 | 3 / J-3 | **Re-scope: I4 withdrawn** — CRC persistent record = operation's emitted S19 + `OperationResult` (not the project/variant report). Folded into I5. |
| 2026-06-16 | 3 / I5a | inject + emit + verify (headless write mechanics); **code-reviewer OK + security-reviewer CLEAN** (mandatory write-path sign-off), F-S-06 folded, **approved + committed** (d67ff48) |
| 2026-06-16 | 3 / I5b | TUI two-stage confirm + write surface; code-reviewer OK (1 MEDIUM F1 fixed); no-write-without-confirm mutation-tested; **approved + committed** (43a2b0f) — **Phase 3 complete** |
| 2026-06-17 | 4 | Validation **PASS-WITH-NOTES** (0 FAIL): 5 HLR/12 LLR PASS, full suite 847/0, surface-reachability CLEAR; **approved + committed** (272b4a7) |
| 2026-06-17 | 5 | Post-mortem (architect + qa): A-4/A-5/KAT controls HELD; J-3 root cause = "named-but-not-read"; 2 new controls + 7 next-batch items; **awaiting gate** |

Full machine log: [`../state.json`](../state.json) `decisions_log`.

---

## 8. What's next

You approve Phase 5 → **Phase 6 (Documentation)** — the last phase: docs-writer updates `REQUIREMENTS.md` (new `R-CRC-*` rows + the `REQ-crc.md` back-reference that was deferred), writes the `06-docs/` traceability matrix + functionality walkthrough + a Mermaid flow diagram, and presentation-builder writes the executive summary. Then **close**: commit + push + PR + review + CI + merge + `/dev-flow-sync` to the Obsidian vault.
