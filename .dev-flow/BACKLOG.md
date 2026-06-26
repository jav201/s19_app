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

### C-1 — dev-flow-sync unfilled-template reject-check ✅ DONE (2026-06-25)
- **Flow:** direct(global ~/.claude). **DONE:** `~/.claude/commands/dev-flow-sync.md` step 3 prose replaced with a concrete structural DETECT (empty required tables/sections, live placeholder tokens as field values, `04-validation.md` with no verdict+results) + anti-false-positive verify-before-block (quoted-guidance/code-fence/frontmatter-example hits are NOT blockers). Global config — not committed to this repo.
- **Why P1 (was):** the RC-1 backstop — batch-14 escaped via a blank Phase-4 artifact; match unfilled *structure*, NOT token substrings (legit prose quotes `<P>`/`TC-NNN`).

### GAP #2 — per-variant file-assignment surface + manifest persistence
- **Flow:** /dev-flow (own batch, scope-first). **Why P1 (after US-015):** net-new feature, larger. PREMISE-CORRECTED — not a wiring fix: TUI save holds no batch/assignments state and there's no per-variant assign surface; `assignments` = *additional* per-variant files (change/check docs), not the primary image. Live: `_write_and_verify_manifest` (`app.py:3548/3591`) writes no batch/assignments; execution service consumes them (`variant_execution_service.py:586-602`).

---

## P2 — Medium (coverage + cleanups to ride soon)

### C-9 — hex-window-content AT for HLR-016 ✅ DONE (2026-06-25, /fast-dev-flow batch claude/fdf-at-gaps)
- **DONE:** 2 black-box ATs added to `tests/test_tui_diff_compare_realpath.py` observing `#diff_hex_a`/`#diff_hex_b` CONTENT through the shipped Compare surface — `test_compare_hex_windows_render_the_differing_bytes` (asserts the exact differing bytes per pane; counterfactual blank-pane RED captured) + `test_compare_hex_windows_report_no_runs_for_identical_images` (the no-run branch, C-10 (b)). 0 source/engine edits.

### CRC-width lock-AT ✅ DONE (2026-06-25, same batch)
- **DONE:** `tests/test_crc_operation.py::test_crc_write_emits_32_byte_records` reads the `write_crc_image`-written `.s19` back as TEXT and locks the fixed 32-byte record width (crc.py:879 emits at the default; the `S19File` map oracle is width-agnostic). Counterfactual 16-byte emit → value-discriminating RED (QC-2). 0 source edits.

### CRC save honours operator-selected record width — DEFERRED feature
- **Flow:** /dev-flow or /fast-dev-flow (own batch). **Why deferred:** `write_crc_image` (crc.py:790) has NO width parameter and hardcodes the default 32 via `emit_s19_from_mem_map(working_mem, working_ranges)` (crc.py:879); US-015's width selector reaches only the Patch Editor save-back, never the CRC operation. Threading a selection through `write_crc_image` + the I5b confirm handler (+ a width source/UI) is net-new feature work. The fixed-32 contract is now LOCKED (above); this item makes it selectable. Parallels the US-015 deferral pattern.

### 4a — app.py ruff F401 cleanup
- **Flow:** direct micro-PR. 5–6 unused imports (`app.py:27/37/38/39/107`), predate recent work. Own PR so it doesn't ride a behavioral change.

### (process) — commit batch-15 `obsidian_synced:true` flip
- **Flow:** direct (ride-along into the first new-branch commit, batch-13 pattern).

---

## P3 — Low (doc/process tidy)

### C-6 — retire provisional TC-230/231 ids ✅ DONE (2026-06-25)
- **DONE — substantively already satisfied; closed with finding.** REQUIREMENTS.md never contained `TC-230`/`TC-231` — §20 (`R-DIFF-LOADFAIL-001`) cites the real node names (`test_at_016_*`), so there was nothing to retire there. The batch-15 archives (`.dev-flow/2026-06-24-batch-15/`) already document every `TC-230`/`TC-231` mention as RETIRED / subsumed-by-AT (V-5); left untouched as a closed + Obsidian-synced historical record (no retroactive rewrite). No live dangling identifier exists anywhere — the only remaining mentions are carry-tracking entries (this item + the batch-14/16 post-mortem carry lists).
- **Flow:** direct. Doc closure (no archive rewrite); rode the F402 `app.py` micro-PR.

### C-10 — AT-authoring discipline ✅ DONE (2026-06-25, reframed) + C-11 ✅ DONE
- **DONE:** encoded in `~/.claude/commands/dev-flow.md` two-layer section — (a) no default-value-reliant pilots (drive a non-default value / cycle off-and-back); (b) one AT per policy branch, asserting *content*. **C-11 ownership** also DONE (qa authors at Phase 1/3; Phase-2 + code-review treat violations as findings).
- **NOTE — original framing superseded:** the first C-10 ("formalize AT-*subsumes*-TC: an AT may replace a TC iff it drives the exact mechanism") was deliberately NOT implemented — the batch-14 post-mortem found AT and TC catch *different* failure classes (the AT caught C3 the TCs structurally couldn't; the AT layer carried the first-cut defects the TCs didn't). Layers kept INDEPENDENT, not consolidated. Documented decision, not an omission.

### RC-1 — Phase-0 base-currency gate ✅ DONE (2026-06-25)
- **DONE:** `~/.claude/commands/dev-flow.md` Phase 0 — `git fetch` + assert merge-base == origin/main tip (rebase if stale) + per-story already-shipped grep → drop SATISFIED-EXTERNALLY at Phase 0. Global config. The headline batch-14 lesson.

---

## Notes
- Items C-1 / C-10 touch global `~/.claude` (outside the repo) — surfaced explicitly per edit, never committed to s19_app.
- Proposed execution order: **US-015 (P0) → C-1 (P1, parallel-safe) → GAP #2 (P1) → C-9 / 4a / obsidian flip (P2) → C-6 / C-10 (P3)**, with P2 cleanups ride-able opportunistically. Operator confirms/reorders.
