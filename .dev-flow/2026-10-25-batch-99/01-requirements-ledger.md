# Requirements ledger — s19_app — Batch 2026-10-25-batch-99

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._

### LED-2026-10-25-batch-99.1 — Phase-2 round 1 iterate-to-refine: blocker Q-1 and every P1-routed major and minor folded
- **Requirement:** HLR-153, HLR-154, HLR-155, HLR-156, HLR-157, HLR-158, HLR-159, HLR-160, HLR-162
- **Requirement:** LLR-152.2, LLR-153.1, LLR-153.2, LLR-153.3, LLR-154.1, LLR-154.2, LLR-154.3, LLR-155.1, LLR-155.2, LLR-155.5, LLR-155.7, LLR-155.8, LLR-156.1, LLR-156.2, LLR-156.3, LLR-156.4, LLR-157.1, LLR-157.2, LLR-157.3, LLR-157.4, LLR-158.2, LLR-158.3, LLR-159.1, LLR-160.1, LLR-160.2, LLR-160.4, LLR-160.5, LLR-162.1, LLR-162.2, LLR-162.3
- **Date:** 2026-10-25
- **What changed (by finding, `02-review.md` round 1; reviewer files `design/P2-architect.md`, `P2-qa.md`, `P2-security.md`):**
  - **Q-1 (blocker)** — no shipped surface calls the A2L encoder (new premise P-22). HLR-158 now carries a recorded exception: the encode limbs are TC-only, and AT-B99-09 observes the decode in the A2L window. Exposing symbol entry in the TUI is routed to the backlog as a feature.
  - **A-1** — LLR-153.1/153.2 name all six S19 record walks and the single data-record predicate (R18). **A-17** — the S0 clause is scoped to S19 output.
  - **A-2, S-5, S-6, S-7, A-20, A-12, Q-14, Q-17** — HLR-155 rewritten. Staging is a private `mkdtemp` directory under `temp/.staging/`, keeping the requested name. Placement is an exclusive claim, then the next free `_<N>`, then `os.replace` with bounded retries and a refusal instead of an exception. The source is never moved. The scope is every `copy_into_workarea` caller. New LLR-155.7 (delete only owned staging, a census) and LLR-155.8 (CRC staging, moved from LLR-159.3 per **A-18**).
  - **A-3, Q-2** — the same-name concurrency RED lives in TC-B99-12 (one requested name). AT-B99-04's RED arm is the duplicate-name refusal; its distinct-name arm is a regression guard. §5.2 is restated.
  - **A-4, A-5, A-6, A-21, Q-5** — HLR-157: the save writes the source plus every current entry and names any entry not applied before. The restore is in place. LLR-157.3 is a name-based census against an exact allow-list. New LLR-157.4: `before_bytes` is the source byte, and its four readers are declared.
  - **A-7, Q-6** — COMPU_TAB representability defined per kind (`TAB_NOINTP` exact; `TAB_INTP` in range and within half a raw step). **A-15** — the RAT_FUNC root pick and an `n/a` decode failure.
  - **A-8** — five loader notice codes; `ARCHITECTURE.md` §11 rows B99-I10..I12; Inc 3 at the 4-file cap.
  - **A-9, Q-12** — the PATCH status rule takes a first-match-wins order; the matrix has 8 cases. **A-10** — `image_ranges` added. **A-22, S-8** — `safe_text` / `md_safe` / `md_code` / `markup=False` made normative. **Q-15** — the flow-report sections are always present; the golden rebaseline is named for Inc 8. **Q-16** — the REPORT block in the AT fixture; D8/D9 clauses TC-only with reasons.
  - **Q-3** — a CRC `error` stops the flow before WRITE-OUT; the statement, AT, threshold and US-148 agree.
  - **Q-4** — AT-B99-02 drives one applied in-image entry (new premise P-23); the all-undone boundary moved to TC-B99-21.
  - **A-16, S-9, S-10, Q-9** — record = a line starting with `S` / `:`; after the end, count only; one notice per kind; S5 ≤ 0xFFFF, S6 ≤ 0xFFFFFF; post-end records never enter the image; controls = every `examples/**/*.s19`.
  - **S-1, S-2, S-3, S-4, S-11, A-19** — HLR-160 rewritten: one ASCII allowlist sanitiser with reserved-device, length and empty rules; containment anchored to the work-area root through `_check_home_contained`, before any mkdir, refusing links; a plan-time collision pass (new LLR-160.5); D8's recommendation changed to `sufijo` on the decisions page.
  - **A-11, Q-10, Q-11** — `refresh_files` and the stored name are declared; `RESERVED_WORKAREA_HOMES` is a closed tuple (B99-I9 aligned); the empty-dialog observable is fixed.
  - **A-13, A-14** — IFC nodes added; Part B now declares 4 COMPONENT blocks. **Q-8** — `#fx_run`. **Q-13** — the overlap corpus class is oracle-only. **Q-7** — a baseline full suite at `a293213` is captured into this batch's evidence.
  - New ids: LLR-155.7, 155.8, 157.4, 160.5; TC-B99-39, 40, 41; P-22, P-23. LLR-159.3 retired (became LLR-155.8, TC-B99-38 kept).
- **Why:** the Phase-2 round-1 review (gate `iterate-to-refine`: 1 blocker, 20 majors, 29 minors) and the orchestrator's rulings, taken under the operator's standing authorization (PLAN header): the encode exception (Q-1) instead of a new UI surface, which would need a prototype round; `RESERVED_WORKAREA_HOMES` over an allow-list, so legacy projects stay listed; D8's recommendation flipped to `sufijo`, because two reviewers showed `reemplazar` breaks H-9's closure and HLR-155's invariant.
- **Evidence:** the reviewer files above; `grep -rn "encode_physical_to_raw_bytes\|add_symbol_entry" s19_app` (P-22); `app.py:3238-3241` (P-23); the measured COMPONENT consumers (`grep -rl <id> s19_app tests` at `a293213`).

### LED-2026-10-25-batch-99.2 — Phase-2 round 2 iterate-to-refine: blocker Q-1 (text), three majors and the minors folded
- **Requirement:** HLR-154, HLR-155, HLR-158, HLR-160
- **Requirement:** LLR-154.2, LLR-155.1, LLR-155.2, LLR-155.7, LLR-155.8, LLR-156.1, LLR-156.4, LLR-157.1, LLR-158.3, LLR-160.1, LLR-160.4, LLR-160.5
- **Date:** 2026-10-25
- **What changed (by finding, round 2 sections of `design/P2-*.md`):**
  - **Q-1 (blocker, text)** — US-147 is restated to the decode the engineer reads in the A2L window. A new maintainer story, US-152, owns the encoder, with the codec API as its surface (the US-141 precedent). HLR-158 traces to both; AT-B99-14 is added.
  - **A2-1 / Q-5 (major)** — LLR-157.3 is retired, together with TC-B99-37: a name-based census over `mem_map` cannot equal any allow-list at HEAD, in either direction. ARQ §2.1's census stays as PDR evidence.
  - **Q-6 (major)** — `TAB_INTP` in-range values are accepted at the nearest raw value, with a flag naming the written physical value; only out-of-range values are refused. `TAB_NOINTP` stays exact.
  - **A2-2 / S-12 (major)** — a BIN and its `.addr` sidecar claim one `_<N>` together before either is written; identical bytes are reused, and the status says so.
  - **A2-3 (major)** — placement failure raises `WorkareaPlacementError`, a subclass of `WorkareaContainmentError`. The `Path` return contract and R19's "zero caller edits" are kept, and the packet lists each caller's handling.
  - **S-13** — the stem is clipped (basename ≤ 200) and the plan pass checks full path length. **S-14** — `temp/.staging` is checked for reparse points. **S-15** — one trailing-record definition (non-empty lines) and the HEX large-tail arm.
  - **A2-4 / Q-22** — §2.8 and §6.3 are re-aligned; map rows B99-I2 and B99-I6 are updated. **A2-5 / Q-18** — the matrix has 8 cases. **A2-6** — IFC nodes completed, GUARD removed. **A2-7** — Part B parents notice; the lane address is COMPUTED. **A2-8** — planning text moved to Rationale lines. **Q-19** — the real id is `patch_entry_bytes_input`. **Q-20** — AT-B99-11 gets a second-export arm. **Q-21** — LLR-155.7 has a decidable census predicate, with the RED site pinned.
- **Why:** the Phase-2 round-2 review (architect 3 major / 5 minor; qa 1 blocker / 2 major / 5 minor; security 1 major / 3 minor), with the orchestrator's rulings under the standing authorization: the census guard is dropped rather than made soft; the `TAB_INTP` rule follows what an honest fixture can build; the placement contract keeps its callers unedited.
- **Evidence:** the round-2 sections of `design/P2-architect.md`, `design/P2-qa.md` and `design/P2-security.md`; `grep -rn "copy_into_workarea(" s19_app` (13 callers); `segment_ops.py:218` (sidecar derivation).

### LED-2026-10-25-batch-99.3 — Phase-2 round 3: majors A3-1, A3-2 and the round-3 minors folded; gate approve
- **Requirement:** HLR-158
- **Requirement:** LLR-155.7, LLR-160.4
- **Date:** 2026-10-25
- **What changed:**
  - **A3-1 (major)** — LLR-160.4: a BIN and its `.addr` sidecar are placed by one call of the new group-placement function `place_group_into_workarea` (map row B99-I2a), because `copy_into_workarea` claims one name per call.
  - **A3-2 (major)** — the decisions page's D4 text now states the amended rule (`TAB_NOINTP` exact; `TAB_INTP` out-of-range refused, in-range accepted with a flag naming the written value). No contract text changed for it.
  - **A3-3** — the A2L IFC flow names the codec API and the A2L window as its sources. **A3-4** — LLR-155.7's predicate binds the path argument of `os.open(..., O_EXCL)`.
  - **Q-23, Q-24** (US-147/US-152 evaluability, the codec-API AT surface in §3 and §5.1) and **S-16, S-17** (pair reuse only when both files are identical; a plan-time path-length arm) were folded as text fixes. They belong to the HLR-158, LLR-160.4 and LLR-160.5 blocks.
- **Why:** P2 round 3 — qa `approve` (2 minors), security `approve` (2 minors), architect 2 majors and 2 minors. The orchestrator folds the majors here and approves P2, naming PDR (architect + qa + ux) as the station that confirms A3-1 and A3-2 against the design proposal, under the standing authorization.
- **Evidence:** the round-3 sections of `design/P2-architect.md`, `design/P2-qa.md` and `design/P2-security.md`; `segment_ops.py:218` (sidecar derived from the BIN name).

### LED-2026-10-25-batch-99.4 — Inc-1 review: the little-endian control uses the ASAM token `MSB_LAST`
- **Requirement:** LLR-158.1
- **Date:** 2026-10-25
- **What changed:** LLR-158.1's threshold named an `LSB_FIRST` control. ASAM MCD-2 MC's BYTE_ORDER tokens are `MSB_FIRST`, `MSB_LAST`, `BIG_ENDIAN` and `LITTLE_ENDIAN`; the app's `_normalize_byte_order` (`tui/a2l.py:280-286`) returns `None` for `LSB_FIRST`. The control now declares `MSB_LAST` on the symbol's RECORD_LAYOUT or tag, and keeps little-endian under a `MSB_FIRST` module. PDR condition PQ-4 item (5) carried the same token; it is read as `MSB_LAST` from now on (the PDR record is sealed and not edited).
- **Why:** code-reviewer, Inc-1 review, finding F1 (HIGH): with `LSB_FIRST` the control passes at HEAD only because MOD_COMMON is ignored, and it turns RED once LLR-158.1 is implemented.
- **Evidence:** `s19_app/tui/a2l.py:280-286`; the Inc-1 review verdict recorded in `03-increments/increment-001.md` §4b.

### LED-2026-10-25-batch-99.5 — Operator verdict on D1–D10 applied; UX-C1 and UX-C7 folded
- **Requirement:** HLR-154, HLR-155, HLR-156, HLR-158, HLR-160, HLR-161
- **Requirement:** LLR-156.2
- **Date:** 2026-10-25
- **What changed:**
  - The operator's verdict (`design/veredicto-b99.json`, exported 2026-10-25T22:32Z) chose the recommended option on every decision: D1 `hex`, D2 `asam`, D3 `modulo`, D4 `rechazar`, D5 `mixta`, D6 `flujo_para`, D7 `rechazar`, D8 `sufijo`, D9 `si`, D10 `diferir`. The 16 "provisional" markers are removed. US-143, US-145, US-147, US-150 and US-152 move to READY.
  - HLR-161 amends batch-07 LLR-001.2: a bare token in the Bytes field is always hex, and decimals are no longer accepted there. Answering the operator's D1 note: String (value) entries are unchanged and keep the document's `encoding` (utf-8 for a new document, `change_service.py:775`).
  - PDR condition **UX-C1** (owned by Inc 8 with the D5 verdict) is folded into LLR-156.2: the lane's terminal run-log line names the PATCH block, the not-applied count and the first address with its disposition.
  - PDR condition **UX-C7** (owned by Inc 9 with the D6 verdict) is folded into HLR-154: an interactive load of a file with an integrity notice leads its status with the defect, never a plain `Loaded <name>`.
- **Why:** the operator verdict of 2026-10-25 and the PDR conditions that waited for it (`design/PDR-2026-10-25-batch-99.md`).
- **Evidence:** `design/veredicto-b99.json`; `design/PDR-ux.md` UX-C1, UX-C7.

### LED-2026-10-25-batch-99.6 — Inc-10 review: per-module byte order and the zero-denominator root become tested clauses
- **Requirement:** LLR-158.1, LLR-158.2
- **Date:** 2026-10-25
- **What changed:** LLR-158.1 gains TC-B99-42: in a multi-MODULE A2L, each module's own `MOD_COMMON BYTE_ORDER` applies to that module's tags. LLR-158.2 gains TC-B99-43: a RAT_FUNC root where the denominator d·P²+e·P+f is zero is no root. Kimi first numbered both TC-B99-26/27, which collided with LLR-159's ids, and the orchestrator renumbered them before merge.
- **Why:** code-reviewer, Inc-10 round 1, LOW-a and LOW-b, fixed in the increment rather than deferred.
- **Evidence:** `03-increments/increment-010.md` §4b; `tests/test_b99_a2l_encode.py`.
