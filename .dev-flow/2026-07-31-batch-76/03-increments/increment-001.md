# Inc-1 — `HLR-108`: the report document is byte-bounded (review packet)

**BLUF.** The document now has a byte gate. Before this increment there was exactly **1** `.fits(`
against **2** `.consume(` calls, and the one gate covered neither `emit` nor five of the six `put`
sites — so the emitted file had no bound at all. Every line into the document now passes one seam,
with a per-variant reservation, an `O(1)` aggregated disclosure, and a round-robin appendix cap.

**Three premises were executed at the open, and two changed the requirement. Three more defects were
found by executing the counterfactuals — all three in acceptances I had just written.**

---

## 1 · What changed

| Clause | Implementation |
|---|---|
| `LLR-108.1/.2` | `_EmissionGate.emit` computes `_line_bytes(batch)`, admits only if it fits, otherwise refuses the batch **whole**, records it, and does **not** latch |
| `LLR-108.3` | `_hexdump_section`'s `put` routes through the same gate — revision 1's exemption is **deleted** |
| `LLR-108.4` | per-variant reservation, floored, charged **alongside** the document budget |
| `LLR-108.5` | each `## Variant:` heading emitted unconditionally |
| `LLR-108.6` | one aggregated `## Omitted content` block at the tail, keyed by a **closed** label tuple; integer variant indices only, capped |
| `LLR-108.7` | `_disclosure_allowance(V)` derived, integer width read from `sys.maxsize` at call time |
| `LLR-108.8` | **AMENDED** — uniform gating **except the `O(1)` header** (see §5) |
| `LLR-108.9` | `_select_notes` retains **round-robin by variant**; tail states the un-itemised count *and* the distinct-variant count |

### Two requirement amendments (Before → After), both driven by executed measurement

| # | Before | After | Driver |
|---|---|---|---|
| **B76-A1** | `LLR-108.8`: "gating shall be uniform … **including the preamble**" | uniform **except the `O(1)` header**; `inventory`/`overview` stay gated and disclosed | **P-16 TRUE.** The preamble is `O(V)` (62.0 then 65.0 B/variant — slopes disagree, so `O(V log V)`) and hits the cap at `V≈32 285`, so literal uniformity refuses the document's own title and contradicts `AT-255`. The spec sketched exempting the *whole* preamble; measurement rejected that — it would put an `O(V)` term inside the allowance (1.33 MB at `V=20 000`) and make `HLR-108`'s `V`-invariance **stated but false**. The header alone is flat at **181 B**. *Operator-approved.* |
| **B76-A2** | `LLR-108.4`: "charged against its own reservation" | …**and against the document budget; an admission requires BOTH** | **P-27, NEW and FALSE.** A floored reservation over-subscribes the document: `Σ = V·max(CAP//V, floor)` = **48.8× CAP** at `V=100 000`, floor 1 024. Reservation-only gating would have broken the very ceiling `AT-250/251/252` assert. |

**Third correction, found while building the AT-254 fixture:** the reservation was being cut from
`REPORT_MAX_TOTAL_BYTES` while the preamble had *already been charged*, so the shares together
exceeded what was actually left. Measured at a 4 000 B limit: preamble ≈ 2 000, yet six shares of
`CAP//6 = 666` promise 3 996 B against 2 000 B available. Now cut from `gate.budget.remaining()`.

---

## 2 · Files modified

| File | Change |
|---|---|
| `s19_app/tui/services/report_service.py` | `+4` constants (all derived) · `_disclosure_allowance` · `_Refusals` · `_EmissionGate` · `_disclosure_lines` · `_select_notes` · `_hexdump_section` re-seamed · `generate_project_report` rewired |
| `tests/test_report_document_bound.py` | **NEW** — 27 nodes: `AT-250…AT-256` + `AT-264` + `TC-552…TC-561` + `TC-573…TC-575` |
| `.dev-flow/2026-07-31-batch-76/00-measurements.md` | **NEW** — the P-16/P-17/P-25/P-27 transcripts |
| `.dev-flow/2026-07-31-batch-76/03-increments/increment-001.md` | this packet |

**2 deliverable files.** Frozen set untouched; `markdown_safety.py` not edited (P-4).

---

## 3 · How to test

```bash
python -m pytest tests/test_report_document_bound.py -q
```

---

## 4 · Test results

**27 passed.** Report suite (`test_report_*`, 341 nodes) **passed with zero regressions**, including
`test_total_bytes_cap_marker`, which drives a shrunken budget and was the node most at risk.

### 4.1 The counterfactual matrix — **executed**, not asserted (C-40)

Each mutation was applied to `report_service.py`, the node run, then the file restored and verified
by **SHA-256 returning to `d13b43e1…4d2a`** (`git status` alone would not have been sufficient). The
harness **fails loudly if an anchor does not match**, so a typo'd mutation cannot masquerade as a red.

| # | Substituted expression | Gates | RED? |
|---|---|---|---|
| M1 | `if not self._budget.fits(cost): return False` → `return True` | AT-250/251/252 | ✅ |
| M2 | reservation `remaining()//max(V,1)` → `remaining()` (global first-fit) | AT-254 | ✅ |
| M3 | `gate.emit_unconditional(_disclosure_lines(...))` → `pass` | AT-253 | ✅ |
| M4 | variant heading `emit_unconditional` → `emit(…, "preamble")` | AT-264 | ✅ |
| M5 | header `emit_unconditional(header)` → `emit(header, "preamble")` | AT-255 | ✅ |
| M6 | round-robin loop → `notes[:cap]` | TC-559 | ✅ |
| M7 | both-budgets check → reservation only | TC-574 | ✅ |
| M8 | `put` → `emit_unconditional` (revision-1 exemption restored) | TC-573 | ✅ |

**INERT: none.** That was **not** the first result.

### 4.2 Three of my own acceptances were inert on first execution

This is the finding of the increment, and every one is the **vacuous-FIXTURE** class — a *correct*
predicate that cannot fail because the fixture never exercises what it asserts. No code mutation
finds these; only mutating the fixture does.

| Node | Why it could not fail | Fix |
|---|---|---|
| **TC-552 caught the first two before I ran anything** | `AT-250`/`AT-251`'s fixtures used `rows=4000`, but `MAX_REPORT_ROWS_PER_VARIANT=200` caps them — the raw output never approached 2 MB. The guard fired on its author. | fixtures re-derived from measurement: 10 variants at `REPORT_BYTES_PER_CELL` width = **4 246 370 B = 2.02× the real cap** |
| **AT-254** | asserted only "every variant has a heading". A heading costs ~20 B and is unconditional, so it survives **any** allocation policy — M2 *and* M4 left it green. It never tested fairness. | added the content clause (each variant gets a real audit record) **and** `AT-264` at a 1-byte budget, where an unconditional emission is the only way a heading can appear |
| **AT-250/252 vs `LLR-108.3`** | restoring revision 1's `put` exemption left them **green** — their fixtures had no `mem_map`, so `_hexdump_section` short-circuited and the five ungated sites were never reached | gave the fixtures a `mem_map`, **and** added `TC-573` asserting the seam directly |

**`TC-573` exists because the ceiling is the wrong instrument for `LLR-108.3`, and that is a
measured fact rather than a preference:** batch-74's `REPORT_MAX_REGIONS_PER_VARIANT` already bounds
one variant's hexdump, so an ungated `put` overshoots by a *bounded* amount per variant; and against
a shrunken limit the ~47 kB allowance dwarfs the limit, so the overshoot hides inside the ceiling's
own slack. Both reasons were found by the mutation staying green, not by reading the code.

### 4.4 Full gate suite — the ONE complete run, evidence read from its own output (C-19/C-25)

```
2455 passed, 2 skipped, 21 deselected, 3 xfailed in 1615.78s
29 snapshots passed.
exit 0
```

**Test ledger reconciles exactly:** `post = base - D + A` = **2428 - 0 + 27 = 2455**. The baseline
2428 is the figure recorded at the AT/TC-registry Lane-A close, and the +27 is exactly this
increment's new nodes — so no existing node was silently deleted, renamed, or skipped to get green.
Snapshots unchanged at 29, which is the expected result for a batch that touches no TUI file.

*(Wall-clock is inflated because two suite runs were contending; the run itself is complete and its
summary line is read from its own output, never stitched across partial runs.)*

### 4.3 Premises executed at the open

| # | Verdict | Evidence |
|---|---|---|
| P-16 | ✅ **TRUE** | preamble `O(V)`, cap reached at `V≈32 285`; header flat at **181 B** from `V=1` to `V=20 000` |
| P-17 | ❌ **FALSE** | **0** golden files contain `## Truncation appendix`; the 3 assertions that mention one each exercise **1** note → any cap ≥ 4 is inert. C-24 census comes back empty. |
| P-25 | ❌ **FALSE** | at `V=1` the reservation **is** the whole cap, so the floor cannot bind; a *saturated* single-variant report measures **26 161 B = 1.25 %** of cap |
| P-27 | ❌ **FALSE (new)** | `Σ reservations` = **48.8× CAP** at `V=100 000`, floor 1 024 |

`AT-256` (PIN): the under-cap report is **byte-identical** to the Inc-0 golden after the rewrite —
the bound is invisible where it does not fire.

---

## 5 · Risks

| # | Risk | Disposition |
|---|---|---|
| r-1 | The allowance (**47 534 B** base) is large relative to a *shrunken* test limit, so ceiling ATs run against a shrunk budget have slack. | Named, not hidden — it is why `TC-573` exists. At the real 2 MB cap the allowance is **2.3 %**. |
| r-2 | `_hexdump_section`'s signature changed (returns notes, no longer lines). | Internal, single caller; full report suite green. |
| r-3 | A tight budget can still leave a late variant with a heading and no content — the floor cannot conjure bytes that do not exist. | **Stated, not papered over.** `AT-254` gates the *allocation policy* (no variant is starved **by another**), not an absolute content guarantee. |
| r-4 | `REPORT_MAX_TRUNCATION_NOTES = 64` is derived from the allowance but is a judgement about *itemisation depth*. | Inert against the whole current suite (P-17, measured). |

---

## 6 · Pending items

- **`REQUIREMENTS.md` is NOT yet updated**, and the **TC-610 amendment** (operator ruling D-4) has
  **not** landed. Both are owed. Until TC-610 is amended, `AT-250…AT-256` **must stay `RESERVED`** in
  the registry — flipping them to `LIVE` reddens it, and citing them as verifiers in
  `REQUIREMENTS.md` while `RESERVED` reddens G4. **Both proven by execution at Phase 0.**
- `TC-561`'s per-arm structural-line count (**7 / 6 / 8 / 7**) is **not** implemented; the shipped
  `TC-561` asserts the disclosure block's `O(1)` line count instead. **Declared, not silently
  dropped.**
- ~~The full gate suite result is recorded at §4 once the background run completes.~~ **DONE — see §4.4.**

---

## 7 · Suggested next task

**Land the owed half of Inc-1** — `REQUIREMENTS.md` + the TC-610 amendment + the registry
`RESERVED`→`LIVE` flip, in that order, since the guard blocks the other two.

Then **Inc-2** (`_format_length`) and **Inc-3** (error re-attribution), in that order — the ordering
is load-bearing: once `_format_length` lands, the natural `Length`-driven `ValueError` disappears, so
Inc-3 must **inject** its fault, which is what makes `AT-260` a *general* attribution test rather than
one welded to the D2 bug.
