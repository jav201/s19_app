# PLAN — batch-58 · CRC Algorithm Designer (Variant B view + engine prerequisites)

> Living compendium. Updated at every gate + significant checkpoint. Human mirror of `state.json`.

## Where we are — ⛔ PAUSED after Phase 2 (two-session collision; awaiting Javier)
- **Phase 0 APPROVED · Phase 1 DONE · Phase 2 DONE (re-gate PASS).** Phase 3 NOT started.
- Branch `feat/batch-58-crc-designer-view` @ base `84180b4`. NOTE: origin/main advanced to `1e3125b` (parallel session's PR #111, docs-only BACKLOG) — this branch is stale-by-1 but NOT rebased (paused).
- Artifacts editor-invisible (worktree-not-editor-root): pasted inline at each gate.

### 🚨 COLLISION + PAUSE (2026-07-20, autonomous decision — escalated to operator)
A **parallel autonomous session** `local_b3ec8612` ("Backlog consolidado por prioridad", PR #111 MERGED, parked/`isRunning:false`) is set up to build **batch-58 (this same feature) autonomously + self-merge**, and believes THIS session is hygiene-only. Javier told THIS session to build batch-58 too, but that grant **predates the collision** and cannot authorize an unattended self-merge into a two-owner conflict.
- **Decision:** stop after Phase 2 (Phases 0-2 = clean, reusable handoff); **NO Phase 3, NO merge.** Keep the primary checkout on this feature branch (NOT `main`) so the other session **stays parked on the true git state and cannot collide**. Await Javier's ownership call.
- **Backstop:** both flows' RC-1 already-shipped grep would catch a merged `#screen_crc_designer` → whoever merges first stops the other.
- **Handoff value:** the expensive part is done — a keel-verified requirements spec (11 US / 11 HLR / 22 LLR / 19 AT, C-35 probes PASS) + a full 3-lens cross-review with the 3 AT-vacuity blockers already folded. Either session can start at Phase 3 from `.dev-flow/2026-07-20-batch-58/` on this branch.

## Objective
Ship the **Variant B CRC Designer TUI view** on the merged batch-57 headless keel, **engine-first**. Preview-only — never writes firmware. Design governed by `docs/crc-algorithm-designer/01-requirements.md` (adopted).

## Scope (operator-confirmed 2026-07-20)
- **All in batch-58**, engine-first increment order.
- **Defer** the `crc.py` width-general wire to a follow-up (stays in BACKLOG).

### Stories
**Engine prerequisites (headless, `s19_app/tui/operations/`, non-frozen):**
- **US-E4** — store endianness/width: `encode_word`/`decode_word(endianness, store_width)` + big-endian; `encode_le`/`decode_le` wrappers byte-identical. (§6 E4, R-CRC-DSN-014/AT-014)
- **US-E5** — template loader `crc_template.py`: collect-don't-abort, reuses `crc_config.py` untrusted posture (resolve_input_path → size cap → json → typed `CrcTemplate` → (None,[err]) never raises). (§6 E5, R-005, AT-015)
- **US-E6** — job up-converter + `emit_job`: parse evolved `crc_config` (algorithm_ref/inline + targets[]) AND back-compat flat (poly/init/reverse/final_xor + regions/groups) into one internal target list; serialize job back. (§6 E6, AT-012 round-trip)

**The Variant B view (`#screen_crc_designer`, Flow-Builder rail-8 pattern):**
- **US-V1** — rail screen + editable form (preset selector + algorithm + serialization); preset populates without overwriting lib. (R-001/006)
- **US-V2** — live KAT verdict: on any field change recompute CRC of `"123456789"`, show computed vs expected `check` with match/mismatch/no-expected. *Centerpiece.* (R-002, AT-016 pilot)
- **US-V3** — custom test vector (hex/ASCII) → computed CRC. (R-003)
- **US-V4** — live round-tripping JSON preview. (R-004)
- **US-V5** — Load/Save through E5 loader; on save enforce `check==compute("123456789")`; warnings `markup=False`. (R-005/007)
- **US-V6** — coverage strip: ordered ranges + intra_gap/join toggles + pad_byte; with image loaded, preview CRC over real bytes for active policy + alternative alongside. (R-008/009, AT-013/013b)
- **US-V7** — gap-conflict surfacing: for `join="fill"` run `gap_conflict` on loaded image, honor `on_gap_conflict` (abort/warn/ignore). (R-011, AT-017)
- **US-V8** — preview-only guard: the view never writes firmware bytes (negative AT). (R-010)

## Keel to reuse (don't rebuild — #110)
- `operations/crc_kernel.py` — `crc_stream`/`crc_lut`, `CrcAlgorithm`, 7-preset catalogue, `compute`/KAT.
- `operations/crc_designer_model.py` — `CrcTemplate`/`CrcJob`/`CrcTarget`, coverage (intra×join), `gap_conflict`/`evaluate_target` (E8), parse/emit (partial).
- Oracles: KAT check(CRC-32/ISO-HDLC)=`0xCBF43926`; coverage `concat=0x9C5BCBBD`, `fill(0xFF)=0x2A8A3950`.

## Roadmap (engine-first; increments cut at Phase 3)
1. E4 (endianness/store_width) → 2. E5 (template loader) → 3. E6 (job up-converter + emit_job) → 4+. View increments (form/KAT → JSON/custom-vector → Load/Save → coverage strip → gap-conflict → preview-only guard).

## Conventions honored
- Engine-frozen set OFF-LIMITS (0 diffs): core/hexfile/range_index/validation/tui/a2l.py/tui/mac.py/tui/color_policy.py + frozen TEST files. `operations/` is non-frozen.
- Docstrings (Summary→Args→Returns→Raises→Data Flow→Dependencies→Example); type hints; ≤5 files/increment; every behavioral change ships an `AT-NNN` shown RED pre-fix.
- Untrusted-text: template-derived text renders `markup=False` (C-17). Template file = new untrusted surface (reuse posture, no new invented).
- Stack-specific gates: consult `docs/engineering-rules.md` at Phase 1/3 (geometry C-13/C-23; snapshot C-22/C-28).

## Key decisions (un-asked, autonomous — full recording)
- **D1 (Phase 1 streamlining):** architect owns `01-requirements.md` end-to-end incl. per-requirement validation method + acceptance blocks (design doc already specifies them); qa-reviewer testability cross-check folded into Phase 2. Rationale: avoid parallel-write race on one file; design doc is already validation-method-complete.
- **D2 (Phase 2 fan-out):** the 3 reviewers write to separate `02-review-{architect,qa,security}.md`; orchestrator consolidates into `02-review.md`. Avoids write races.

## Risks / watch-items
- **RK-6 perf** (closed by E7 LUT keel) · **RK-7 gap divergence** (closed by E8 keel) · **RK-3** refin≠refout KAT-unverified (round-trip test only) · **RK-4** big-endian store needs a device fixture (E4 designed).
- Batch SIZE is large (10 stories, new full TUI screen) — split at a phase boundary if it overruns.
- C-16 prototype-fidelity: the HTML/py prototype proves DESIGN INTENT; Textual interactions (arrow-nav, focus) are `assumed — verify at Phase 3` and ATs must drive the REAL mechanism.
- C-17 markup-safety: the view renders template/file-derived text — mandatory markup=False LLR + hostile-input AT at Phase 1.

## Out-of-scope carries (to BACKLOG at close)
- Wire width-general kernel into shipped `crc.py` operation (deferred by operator).
- §9 extension points: `operation:"checksum"`, `serialization.align`, reflected-form poly entry.

## Test ledger
- Base (batch-57 close): CRC designer tests = 45. Full suite baseline captured at Phase-4 gate run.

## Decision log (mirror of state.json.decisions_log)
- 2026-07-20 Phase 0: kickoff + intake APPROVED (autonomous+self-merge, English). Scope: all-in-b58 engine-first; defer crc.py wire. RC-1 PASS @ 84180b4.
