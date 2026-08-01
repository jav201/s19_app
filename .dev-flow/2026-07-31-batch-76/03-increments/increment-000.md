# Inc-0 — pre-flight golden capture (review packet)

**BLUF.** The `AT-256` baseline is captured from the **shipped, unmodified** producer at
`origin/main` = `291bb76` and committed **before any producer edit**, so it cannot certify the
`HLR-108` rewrite against itself (C-12). The fixture is deliberately over-covered: it reaches the
hexdump **block loop** with 63 real dump lines and exercises the `Length` column, so the pin is not
vacuous in the places this batch changes. No production code changed.

---

## 1 · What changed

Test data and its provenance only — **zero production code, zero behaviour**.

- Captured `tests/goldens/batch76/document-bound-preflight.md` (**7 619 B**, 217 lines) by running
  the shipped `generate_project_report` over a frozen fixture with an injected clock.
- Committed the capture script alongside it, so the golden's provenance is re-runnable rather than
  asserted. Ordering is auditable: `git log --diff-filter=A -- tests/goldens/batch76/`.

**Why the fixture is over-covered, not minimal.** The new vacuity class registered in Lane B is the
**vacuous FIXTURE** — a correct predicate that cannot fail because the fixture never exercises what
it asserts. A minimal fixture would short-circuit `_hexdump_section` at its "No modified regions" or
"Post-change memory map unavailable" guard, leaving the batch's own gating change **unpinned**. So:

| Seam this batch touches | How the fixture reaches it | Measured |
|---|---|---|
| per-variant reservation (`LLR-108.4`) + unconditional heading (`LLR-108.5`) | `V = 3`, not 1 | 3 `## Variant:` blocks |
| the 5 **ungated** `put()` sites **and** the 1 gated `put(block)` at `:1788` | `mem_map` populated over the applied regions | 3 `### Memory regions`, **63** hexdump data lines, **0** short-circuits |
| `_applied_regions` returning a real region list | mixed `applied` / `skipped` dispositions | non-empty |
| the second `Length` site (Inc-2) | checks present, mixed pass/fail | 3 `### Checklists` |

---

## 2 · Files modified

**Deliverable (2):**

| File | Change |
|---|---|
| `tests/goldens/batch76/document-bound-preflight.md` | **NEW** — the pre-flight golden, 7 619 B |
| `.dev-flow/2026-07-31-batch-76/inc0-capture-golden.py` | **NEW** — the capture script |

**Flow bookkeeping (3):**

| File | Change |
|---|---|
| `.dev-flow/2026-07-31-batch-76/PLAN.md` | **NEW** — living plan, RC-1, authorization, premise re-execution |
| `.dev-flow/state.json` | batch-75 → batch-76; re-read immediately before writing (last-writer-wins) |
| `.dev-flow/2026-07-31-batch-75/state-at-close.json` | **NEW** — archived; batch-75 referenced it but never committed it to its own dir |

≤5 constraint honoured: **2 deliverable files**; the other 3 are flow records with no behaviour.

---

## 3 · How to test

```bash
python .dev-flow/2026-07-31-batch-76/inc0-capture-golden.py
```

Re-running must reproduce the golden **byte-for-byte**; any drift means the fixture and the golden
have separated, which is the correct signal (batch-74 precedent).

---

## 4 · Test results

| Check | Result |
|---|---|
| Determinism — capture run twice | ✅ identical SHA-256 `43312afb…e7b85` both runs |
| Under-cap margin — **measured, not assumed** | ✅ 7 619 B against a 2 097 152 B cap = **0.3633 %**, headroom 2 089 533 B |
| Hexdump short-circuits | ✅ **0** — neither "No modified regions" nor "Post-change memory map unavailable" |
| Real hexdump data lines | ✅ **63** |
| `Length` column exercised | ✅ values 1–4 across 3 variants (pins Inc-2's in-domain rendering too) |
| Truncation appendix | **absent** — correct: nothing is capped under budget. Recorded as the P-17 starting state. |
| Toolchain entry gate | ✅ Python 3.14.4 · pytest 8.4.2 · ruff 0.15.17 |
| Frozen set | ✅ untouched — no file in the frozen SOURCE or TEST set is in this diff |

---

## 5 · Risks

| # | Risk | Disposition |
|---|---|---|
| r-1 | The fixture is duplicated verbatim into the Inc-1 test (a test may not import from `.dev-flow/`). | Accepted, batch-74 precedent. Drift makes `AT-256` fail, which is the correct signal — the golden would no longer describe the fixture. |
| r-2 | The golden pins **more** surface than `HLR-108` touches (legend, entropy, overview), so an unrelated change reddens it. | Intended — it is a **collateral-damage PIN**, not a gate. Labelled as a PIN in the spec and here, per Phase-2 M-1. It cannot discriminate the change and is not offered as if it could. |
| r-3 | The golden embeds a host temp path. | Not carried: capture runs in a `TemporaryDirectory` and the Inc-1 assertion goes through `conftest.canonical_report_bytes`, the same normaliser `AT-247` uses. |

---

## 6 · Pending items

- `AT-256`'s **test node** is not written yet — it belongs to Inc-1, which owns `AT-250…AT-256`.
  Inc-0 only *enables* it. Until that node exists the golden is inert data, and this packet does
  not claim otherwise.
- **P-16 / P-17 / P-25** remain **UNDECIDABLE** and are resolved by execution at Inc-1, not assumed.
- The **TC-610 amendment** (operator ruling D-4) lands at Inc-1, with the ids it frees.

---

## 7 · Suggested next task

**Inc-1** — `emit` + `put` gating · per-variant reservation · aggregated `O(1)` disclosure · capped
round-robin appendix · derived allowance. Owns `AT-250…AT-256` and `TC-552…TC-561`.

**Inc-1 must open by executing P-16, P-17 and P-25** — they are requirement-strength questions, and
if P-16 is TRUE, `LLR-108.8` flips to an explicit exemption and the allowance grows. That is
surfaced at the gate, never absorbed silently.
