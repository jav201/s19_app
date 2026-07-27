# batch-63 — Phase-0 execution probe transcript

> **Purpose:** the defect is MEASURED on the current tree before any requirement text exists
> (C-35 draft-time execution probe; C-39 pre-execute every executable threshold). Nothing in this
> batch's spec is inherited from the backlog's prose.

**Tree:** branch `claude/batch-63-report-table-caps` @ base `031ca8d` (== `origin/main` tip), clean.
**Probe:** `scratchpad/p63.py` — builds real `VariantExecutionResult` fixtures, calls the shipped
`generate_project_report`, re-reads the written `.md` from disk, counts emitted table rows.
**Python:** 3.14.4. **Caps read from disk:** `REPORT_MAX_REGIONS_PER_VARIANT=128`,
`MAX_REPORT_ISSUES_PER_VARIANT=200`, `REPORT_MAX_TOTAL_BYTES=2 097 152`.

---

## M-1 — both tables are strictly unbounded (realistic regime)

Symbol = `ASAM.C.SCALAR.UBYTE.IDENTICAL.CalibrationValue_Bank1_Cylinder04_<i>` (63 chars + index),
a realistic A2L name — per-row cost is decided by this field, so a 1-char placeholder would have
measured the wrong thing.

```
caps on disk: REGIONS=128 ISSUES=200 TOTAL_BYTES=2,097,152
N=   200 | mod_rows=   200 | chk_rows=   200 | size=    51,876 B | over_budget=no  | bytecap_marker=no
N=  1000 | mod_rows=  1000 | chk_rows=  1000 | size=   182,286 B | over_budget=no  | bytecap_marker=no
N=  5000 | mod_rows=  5000 | chk_rows=  5000 | size=   838,288 B | over_budget=no  | bytecap_marker=no
N= 20000 | mod_rows= 20000 | chk_rows= 20000 | size= 3,291,816 B | over_budget=YES | bytecap_marker=fired
```

**Result:** `rows == N` at every N, in **both** tables. No bound exists.
Slope (both tables together): (3 291 816 − 838 288) / (20 000 − 5 000) = **163.6 B per entry**
→ ~81.8 B per row. Budget crossed at **≈12 700 entries**.

## M-2 — the truncation marker asserts a bound the document violates

At N=20 000 the document contains:

```
> TRUNCATED: … hexdump block(s) omitted (report size cap: 2097152 bytes).
```

…while the file on disk is **3 291 816 bytes = 1.57× that cap**. The marker fires because
`_hexdump_section` consulted `budget.fits()` and omitted its blocks; the two tables that actually
consumed the budget are never checked against it. The document therefore *states* an enforced size
cap it does not honor.

This is the finding that raises the item above "resource hygiene": in an evidentiary document a
truncation notice that fires while the stated bound is violated is worse than no bound, because a
reader takes the notice as proof the bound held.

## M-3 — per-row cost spread: 3.7× (decides the cap SHAPE)

Same probe, symbol replaced by 512 `X` (the `REPORT_CELL_CHARS` ceiling — the largest cell the
escaper will emit):

```
PATHOLOGICAL regime (512-char symbol):
N=   200 | mod_rows=   200 | chk_rows=   200 | size=   142,386 B | over_budget=no  | bytecap_marker=no
N=  1000 | mod_rows=  1000 | chk_rows=  1000 | size=   634,396 B | over_budget=no  | bytecap_marker=no
N=  5000 | mod_rows=  5000 | chk_rows=  5000 | size= 3,077,916 B | over_budget=YES | bytecap_marker=fired
```

Slope: (3 077 916 − 634 396) / (5 000 − 1 000) = **610.9 B per entry** → budget crossed at
**≈3 400 entries**.

| regime | cost / entry | N at budget |
|---|---:|---:|
| realistic (63-char symbol) | 163.6 B | ~12 700 |
| pathological (512-char symbol) | 610.9 B | ~3 400 |
| **spread** | **3.7×** | **3.7×** |

**Consequence for the design ruling (Phase 1):** a fixed **row** cap is predictable and per-variant
fair but cannot bound bytes — the same cap yields 3.7× different document sizes. The **byte budget**
bounds bytes but is not fair across variants (the first variant would consume the whole allowance).
Phase 1 rules the shape *by executing both candidates*, not by preference.

## M-4 — mechanism: the budget is accounted but never enforced on the tables

`generate_project_report`'s local `emit()` (`report_service.py:1634`) does
`lines.extend(batch); budget.consume(_line_bytes(batch))` — so the tables **are** charged to
`_ByteBudget`. But `budget.fits(...)` is consulted **only** inside `_hexdump_section`
(`report_service.py:1347`). Accounting without enforcement: the tables grow without limit *and*
starve the hexdumps that do respect the budget.

This corrects the backlog's framing ("charge them to `_ByteBudget`") — they are already charged;
the missing half is the check.

## M-5 — no bound on the variant axis

`grep -rn "MAX_VARIANT\|max_variants\|MAX_PROJECT_FILES" s19_app/` → **no matches**.
`validate_project_files` imposes no count limit. Document size therefore also scales with variant
count, independently of these two tables. Pre-existing and orthogonal → recorded as a BACKLOG
carry, **out of scope here** (it affects every per-variant section, not these tables).

## M-6 — probe self-correction (recorded, not hidden)

The first run reported `chk_rows = -1`. Cause: the checklist heading is emitted as
`` #### Checklist: `chk.json` `` — a Mode-B code span — while the predicate searched for the bare
`#### Checklist: chk.json`. **The predicate was wrong; the artifact was correct.**

Third instance of this family in three batches (batch-61's NBSP-entity predicate reporting 0/19
against a valid artifact; batch-62's `"](" not in note` failing a correct implementation). It is
the standing un-encoded control candidate **P-3 — assert against the emitted encoding, never the
rendered form or a character list**. Logged here as a fresh occurrence for that candidate's count.

Worth noting *why* it was caught: the probe returned an **impossible** value (−1, "heading absent")
rather than a plausible one. A predicate that had merely under-counted would have passed unnoticed.
