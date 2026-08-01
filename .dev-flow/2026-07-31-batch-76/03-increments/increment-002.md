# Inc-2 — `HLR-109`: the `Length` cell renders (review packet)

**BLUF.** `_format_length` is **created** (it did not exist — P-6, 0 hits) and both emission sites
route through it. A `Length` whose decimal width exceeds `sys.get_int_max_str_digits()` now renders
as a bounded hex token carrying its sign and stating what was elided, instead of raising and denying
the whole report. **19 nodes, 8 counterfactual mutations, INERT: none.**

⚠️ **This is hardening, not a live defect** — re-triaged P3 on 2026-07-31 and the packet says so
rather than dressing it up. Both construction sites derive `Length` from `entry.addressed_range`, so
`end − start == len(encoded_bytes)`, bounded by `MF_RUN_LENGTH_CEILING = 1 048 576` → **7 decimal
digits against a 4 300 limit**. The negative arm is constructor-only too (`len(encoded_bytes) ≥ 0`).
**No test here claims a change-document route.**

---

## 1 · What changed

| Clause | Implementation |
|---|---|
| `LLR-109.1` | `_format_length(value: int) -> str` **created** in `report_service` |
| `LLR-109.2` | domain test = integer-safe **upper** bound on decimal width from `bit_length()` vs `sys.get_int_max_str_digits()` read **at call time**; `0` ⇒ always in-domain; `str(value)` never evaluated on the untested path |
| `LLR-109.3` | shortened form keeps the top `REPORT_LENGTH_HEX_DIGITS` hex digits **by shift, never by format-then-slice**, carries `-`, appends the elided-count cue |
| `LLR-109.4` | `REPORT_LENGTH_HEX_DIGITS = REPORT_ADDRESS_HEX_DIGITS` — reused, not a fourth policy number |
| `LLR-109.5` | both producers call the formatter; **0** inline `address_end - address_start` f-strings survive |
| `LLR-109.6` | every character of the **whole emitted token** ∉ `MD_ESCAPE`, executed against the real tuple |

### The one design decision worth recording

**In-domain renders DECIMAL, not hex** — unlike `_format_address`, which is hex in-domain because
*addresses* are hex in the shipped output. `Length` is decimal there. This is not a style
preference: `AT-256` pins the whole under-cap document against the Inc-0 golden, and that golden
carries `| 1 |`, `| 2 |`, `| 3 |`, `| 4 |`. Rendering hex in-domain would drift **every** `Length`
cell in the repository. Verified: the golden is byte-identical after this increment, and mutation
**M8** (in-domain → hex) reddens `TC-566` *and* `AT-256` together.

**Line numbers re-derived, never copied.** The spec cites `:1356` / `:1582`; at this branch the
sites are **`:1881`** and **`:2107`**, shifted by Inc-1. The backlog's standing warning that every
line number in this module is stale in both directions held again.

---

## 2 · Files modified

| File | Change |
|---|---|
| `s19_app/tui/services/report_service.py` | `+2` constants (`REPORT_LENGTH_HEX_DIGITS`, the `log10(2)` rational) · `_decimal_width_upper_bound` · `_format_length` · both call sites |
| `tests/test_report_length_cell.py` | **NEW** — 19 nodes: `AT-257…AT-259` · `TC-562…TC-569` · `TC-576` · `TC-577` |
| `tests/test_id_registry.py` | `EXPECTED_SCANNED_TEST_FILES` 150 → 151, in the same PR as its guard requires |
| `.dev-flow/2026-07-31-batch-76/03-increments/increment-002.md` | this packet |

**2 deliverable files.** Frozen set untouched; `markdown_safety.py` not edited (P-4).

---

## 3 · How to test

```bash
python -m pytest tests/test_report_length_cell.py -q
```

---

## 4 · Test results

**19 passed.** With Inc-1 + the id guard + the shipped report suite: **32 passed**, no regressions.

### 4.1 Counterfactual matrix — executed, restored, hash-verified

Source restored to `6a961dfb…dfab` after every mutation.

| # | Substituted expression | Gates | RED? |
|---|---|---|---|
| M1 | shortened `f"{sign}0x{leading:0{kept}X}"` → `f"{sign}{leading:0{kept}X}"` | AT-257/258 | ✅ |
| M2 | `sign = "-" if value < 0 else ""` → `sign = ""` | AT-259 | ✅ |
| M3 | `sys.get_int_max_str_digits()` → typed `4300` | TC-564 | ✅ |
| M4 | arithmetic shift → `return str(value)[:64]` (format-then-slice) | TC-568 | ✅ |
| M5 | one call site reverted to the inline f-string | TC-562 | ✅ |
| M6 | width bound loses its `+ 1` (understates) | TC-577 | ✅ |
| M7 | cue gains `.` — a live `MD_ESCAPE` character | TC-569 | ✅ |
| M8 | in-domain `str(value)` → `f"0x{abs(value):X}"` | TC-566 **and** AT-256 | ✅ |

### 4.2 Two defects in my own fixtures, and one in the mutation harness itself

| # | What was wrong | How it surfaced |
|---|---|---|
| f-1 | `TC-567`'s forgery fixture used `REPORT_LENGTH_HEX_DIGITS + 40` hex digits ≈ **67 decimal digits** — far inside the 4 300 limit, so it rendered decimally and **never reached the shortened branch it claims to test**. | node failed on the correct implementation |
| f-2 | `AT-259` asserted `_expected_token(_HUGE) not in text` to prove the sign survived. But `"-0xFFF…"` **contains** `"0xFFF…"`, so the check is satisfied by correct output and discriminates nothing. Compared as **cells** now (`\| token \|`). | node failed on the correct implementation |
| **h-1** | **The mutation harness reported a false GREEN.** `_format_address` and `_format_length` carry a **byte-identical** `return` block, so `replace(old, new, 1)` mutated the *wrong function* while reporting `applied=True`. M1 read as INERT for a reason that had nothing to do with `AT-257`. | caught by re-reading the anchor, not by any test |

**h-1 is the one worth carrying.** C-40 warns that a typo'd mutation "also fails, for the wrong
reason"; this is the **inverse and more dangerous** case — an *ambiguous* anchor **fails open**,
reporting a node inert when the mutation never touched the site under test. The harness now
**refuses to run any mutation whose anchor matches more than once** (`ANCHOR AMBIGUOUS ×N`), which
makes the failure loud instead of silent. Proposed as a control candidate in §7.

---

## 5 · Risks

| # | Risk | Disposition |
|---|---|---|
| r-1 | `TC-564` mutates a **process-global** (`sys.set_int_max_str_digits`). | Restored in `finally`; documented as non-parallel. It is the C-39 node — the boundary must be executed, not typed. |
| r-2 | The width bound deliberately **over**-estimates, so a value just under the limit may shorten unnecessarily. | Intended and asserted (`TC-577` sweeps 54 magnitudes). Under-estimating would admit the very `ValueError` being closed; over-estimating only costs a slightly early cue. |
| r-3 | `TC-566`'s negative in-domain arm is **unfalsifiable by mutation** — an f-string preserves the sign unconditionally. | **Labelled a PIN**, not counted as a gate (Phase-2 m-3). Recorded rather than quietly counted as coverage. |
| r-4 | Shortened-vs-shortened collision is not covered: two values sharing their top 16 hex digits **and** elided count render identically. | Non-claim (k), inherited from `_format_address`. The cue announces incompleteness; the claim is only shortened ≠ *complete*. |

---

## 6 · Pending items

- **Reported as found, not fixed:** `ruff F821 Undefined name 'Dict'` at `s19_app/tui/app.py:5682`.
  **Verified PRE-EXISTING** by running ruff against a pristine `origin/main` copy of the file — it is
  not this batch's, and it is out of scope. It is harmless at runtime (`from __future__ import
  annotations` defers evaluation). → `BACKLOG-CODE.md`.
- `REQUIREMENTS.md`, the **TC-610 amendment**, and the `RESERVED`→`LIVE` flip remain **owed**, in
  that order — the guard still blocks the other two.

---

## 7 · Suggested next task

**Inc-3** — error re-attribution (`app.py`), owning `AT-260…AT-263` and `TC-570…TC-572`. Ordering
holds: `_format_length` has now landed, so the natural `Length`-driven `ValueError` is gone and
Inc-3 **must inject** its fault — which is exactly what makes `AT-260` a *general* attribution test
rather than one welded to the D2 bug.

**Control candidate for Lane B (h-1): a mutation anchor must be unique, and ambiguity must fail
loud.** A substituted expression that matches at more than one site does not test the site it names,
and it fails OPEN — reporting a live predicate as inert. Distinct from the "typo'd mutation" case
C-40 already records, because there the mutation does not apply at all; here it applies, to the
wrong code, and reports success. Discharge: count the anchor's occurrences and refuse to run unless
it is exactly 1.
