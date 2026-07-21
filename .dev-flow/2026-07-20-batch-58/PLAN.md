# PLAN — batch-58 · CRC Algorithm Designer (Variant B view + engine prerequisites)

> Living compendium. Updated at every gate + significant checkpoint. Human mirror of `state.json`.

## Where we are — Phase 3 (Implementation) IN PROGRESS
- **Phase 0 APPROVED · Phase 1 DONE · Phase 2 DONE (re-gate PASS) · Phase 3 STARTED.**
- Branch `feat/batch-58-crc-designer-view` **rebased onto `origin/main` `1e3125b`** (RC-1 currency restored; base ref now `1e3125b`).
- Artifacts editor-invisible (worktree-not-editor-root): pasted inline at each gate.

### ✅ COLLISION RESOLVED (2026-07-21)
A parallel session `local_b3ec8612` was also set up to build batch-58. I paused after Phase 2 and escalated; **Javier adjudicated live: THIS session owns batch-58 from Phase 3.** Stand-down message delivered to the parallel session; it stays parked (primary checkout intentionally NOT on `main`). Mutual backstop: RC-1 already-shipped grep catches a merged `#screen_crc_designer`.

### Phase-3 increment cut (engine-first, ≤5 files each)
| Inc | Scope | LLR | AT | Notes |
|---|---|---|---|---|
| 1 | E4 word codec — `crc.py` `encode_word`/`decode_word` (big+wide) + `encode_le`/`decode_le` wrappers | E4.1/.2/.3 | AT-CRC-DSN-014 | new `test_crc_word_codec.py` |
| 2 | E5 `crc_template.py` facade (re-export loader from `crc_designer_model`) | E5.1/.2 | AT-CRC-DSN-015 | new `test_crc_template_loader.py` |
| 3 | E6 `parse_job` flat up-convert branch + `emit_job` (`crc_designer_model.py`) | E6.1/.2/.3 | AT-058-01, AT-CRC-DSN-012 | new `test_crc_job_upconvert.py`; back-compat fixtures unchanged |
| 4 | View scaffold + rail wiring (key `0`/glyph `⊕`/`R`) + form + preset population | V1.1/.2 | AT-058-02 | screen file + app.py rail edits; **C-22/C-28 snapshot census** |
| 5 | Live KAT verdict (recompute-on-change) + custom vector + JSON preview | V2.1/.2, V3.1, V4.1 | AT-CRC-DSN-016/011, AT-058-03/04 | centerpiece; before/after single-event AT |
| 6 | Load/Save + save-time KAT + markup-safety + 3 warn conditions | V5.1/.2/.3/.4 | AT-058-05/10/06, AT-CRC-DSN-015 | markup=False all sinks incl JSON preview |
| 7 | Coverage strip + per-policy preview + gap-conflict + preview-only guard | V6.x, V7.1, V8.1 | AT-058-07/08/09, AT-CRC-DSN-013/013b/017 | §3.2 fixture oracle |

`software-dev` implements per increment (review packet each); `code-reviewer` independent review at each gate; self-approve with a named Coverage/Certainty/Evidence axis check.

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
