# s19_app — dev-flow BACKLOG (cross-batch, prioritized)

> Single prioritized queue for all open work: the in-flight batch-14 item + the 2026-06-23/24 audit carries. Continue (do not pivot). `origin/main` tip = `9169130` (batch-15 PR #20 + audit-gaps PR #21 merged). Engine-frozen set OFF-LIMITS: core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py. All repo work on a fresh branch off `origin/main`; `pytest -q` to verify; ≤5 files/increment; every behavioral change ships a black-box AT shown failing pre-fix; commits/PRs only on operator approval.

## Status legend
`P0` critical/next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct, direct(global ~/.claude)}

---

## P0 — Critical (continue batch-14)

### US-015 — Selectable 16/32 S19 record width + populated S0 header
- **Flow:** /dev-flow (the batch-14 we are continuing). **Status:** Phase 1 complete (2 HLR / 7 LLR / TC-212..226 + AT-015.1-.3 / AT-016.* · spec at `.dev-flow/2026-06-23-batch-14/01-requirements.md`).
- **Why P0:** data-fidelity/interop — downstream flashing/diff tools need 32-byte records + header; emitter is hardcoded 16-byte + empty S0 (`tui/changes/io.py:1409/1473/1471`). Confirmed net-new, never built.
- **Critical watch:** the 16→32 default flip has back-compat blast radius (Phase-1 finding D2: 0 tests assert a 16-byte *row width*, but re-confirm on current main). Cross-format integrity guarded by TC-226 (S19↔HEX round-trip, `emit_intel_hex_from_mem_map io.py:1533` untouched).
- **Build-on:** rebase batch-14 branch onto `origin/main 9169130` so US-015 sits atop the shipped US-016. Emission stays in `tui/changes/io.py` (outside frozen set).

### US-016 — A↔B compare load-failure honesty  ✅ SATISFIED (batch-15, main §20)
- Shipped in PR #20 (`R-DIFF-LOADFAIL-001`). No duplicate work. Kept here for traceability; its coverage gap is C-9 below.

---

## P1 — High (process backstop + key feature)

### C-1 — dev-flow-sync unfilled-template reject-check
- **Flow:** direct(global ~/.claude). **Why P1:** the RC-1 backstop — batch-14 escaped via a blank Phase-4 artifact; this is the highest-value process fix and should land before the big feature batches so they run hardened. **Care:** match unfilled *structure* (placeholder tokens in required rows, empty required sections, 04-validation with no executed results), NOT token substrings — legit prose quotes `<P>`/`TC-NNN`.

### GAP #2 — per-variant file-assignment surface + manifest persistence
- **Flow:** /dev-flow (own batch, scope-first). **Why P1 (after US-015):** net-new feature, larger. PREMISE-CORRECTED — not a wiring fix: TUI save holds no batch/assignments state and there's no per-variant assign surface; `assignments` = *additional* per-variant files (change/check docs), not the primary image. Live: `_write_and_verify_manifest` (`app.py:3548/3591`) writes no batch/assignments; execution service consumes them (`variant_execution_service.py:586-602`).

---

## P2 — Medium (coverage + cleanups to ride soon)

### C-9 — hex-window-content AT for HLR-016
- **Flow:** /fast-dev-flow. **Why:** HLR-016 says "render the differing bytes in the hex windows" but no AT observes pane content — a blanked-pane defect passes today's 4 ATs. Test-centric, on shipped compare.

### 4a — app.py ruff F401 cleanup
- **Flow:** direct micro-PR. 5–6 unused imports (`app.py:27/37/38/39/107`), predate recent work. Own PR so it doesn't ride a behavioral change.

### (process) — commit batch-15 `obsidian_synced:true` flip
- **Flow:** direct (ride-along into the first new-branch commit, batch-13 pattern).

---

## P3 — Low (doc/process tidy)

### C-6 — retire provisional TC-230/231 ids in REQUIREMENTS.md / dev-flow docs
- **Flow:** direct. Doc cleanup.

### C-10 — formalize the "AT-subsumes-TC" criterion in the dev-flow
- **Flow:** direct(global ~/.claude). An AT subsumes a planned white-box TC iff it drives the exact mechanism with no mock AND exercises every named LLR boundary.

---

## Notes
- Items C-1 / C-10 touch global `~/.claude` (outside the repo) — surfaced explicitly per edit, never committed to s19_app.
- Proposed execution order: **US-015 (P0) → C-1 (P1, parallel-safe) → GAP #2 (P1) → C-9 / 4a / obsidian flip (P2) → C-6 / C-10 (P3)**, with P2 cleanups ride-able opportunistically. Operator confirms/reorders.
