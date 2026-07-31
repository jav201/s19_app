# batch-74 — Phase 0 measurements (C-43 premise evaluation · C-39 executed thresholds)

**Base:** `origin/main` = **`d81cb3d`** · measured 2026-07-31 · Python 3.14.4 (host), CPython default
`int_max_str_digits = 4300`.

> **BLUF — three of the plan's premises hold exactly, one is FALSE, and the false one changes the
> design.** The plan (and the backlog it inherits) states the OB-4 cost as a flat **988 B/entry**.
> Measured, the per-entry cost is **not a constant**: it is **linear in the entry's byte-run length**
> (~6 B of rendered row per byte of run). 988 B/entry is the value at a ~149-byte run. Consequently
> **a row-count cap alone does not bound resident memory** — which is precisely the bound the plan's
> Inc-1/Inc-2 sketch proposes. The producer must bound **two** axes, not one.

---

## 0. Base-move re-verification (the plan was authored at `6524afd`)

`origin/main` advanced `6524afd → 37f2a4b → d81cb3d` between plan authoring and execution.

```
git diff --stat 6524afd d81cb3d -- s19_app/tui/services/report_service.py
  (empty — 0 lines changed)
```

**Every `@6524afd` address in the plan is therefore still valid at `d81cb3d`.** Re-confirmed
individually in §1. `report_service.py` measures **2262** lines at both commits.

Flow currency (C-45 PULL): local `~/.claude` aggregate `sha256 = 0127a2767ff11c8a` = FLOW-VERSION
**`2026.07.28-rev1`** EXACT.

---

## 1. Premise table (C-43)

| # | Premise (as stated in the plan) | Tier | Verdict | Executed evidence |
|---|---|---|---|---|
| P-1 | `_modifications_lines` at `:1031`, spans `:1031`–`:1111` | premise | ✅ TRUE | `def _modifications_lines(` at `report_service.py:1031`; `return lines` at `:1111` |
| P-2 | `_checklist_lines` starts `:1203` | premise | ✅ TRUE | `def _checklist_lines(` at `:1203` |
| P-3 | `MAX_REPORT_ISSUES_PER_VARIANT = 200` at `:96`, consumed at `:1122` inside `_declaration_error_lines` (`:1114`) — a **third**, adjacent function; the two targets stay uncapped | premise | ✅ TRUE | constant at `:96`; `_declaration_error_lines` at `:1114`; its cap arm at `:1151-1153`; docstring mention at `:1122`. Neither target function references any cap constant |
| P-4 | `REPORT_MAX_REGIONS_PER_VARIANT = 128` (`:83`) consumed **only** by `_hexdump_section` | premise | ✅ TRUE | constant `:83`; sole consumption in `_hexdump_section` (`:1369`) at `:1437-1442`; module comment `:168-171` states it itself |
| P-5 | `_ByteBudget` declared `:506`, instantiated once `:2211` | premise | ✅ TRUE | `class _ByteBudget` `:506`; `budget = _ByteBudget(limit=REPORT_MAX_TOTAL_BYTES)` `:2211`, single occurrence |
| P-6 | **Charging these tables to `_ByteBudget` closes F4 and leaves OB-4 untouched** (the load-bearing design constraint) | premise | ✅ TRUE | `emit()` (`:2215-2217`) calls `budget.consume(...)` only — it **accounts, never gates**. The sole `budget.fits(...)` gate is `_hexdump_section:1455`. `emit(_modifications_lines(...))` at `:2243` fully evaluates the producer **before** `consume` is reached |
| P-7 | D2: `_ADDRESS_RE` has no digit limit, so a ≥3572-hex-digit address is schema-legal | premise | ✅ TRUE | `_ADDRESS_RE = re.compile(r"^0x[0-9A-Fa-f]+$")` — `changes/io.py:235` |
| P-8 | D2: hex renders fine, the **decimal** `Length` raises | premise | ✅ TRUE | executed: `f'{n:X}'` OK at 3601 digits; `f'| {n} |'` → `ValueError: Exceeds the limit (4300 digits) for integer string conversion` |
| P-9 | D2: the boundary is **not** a stable literal — derive from `sys.get_int_max_str_digits()` | premise | ✅ TRUE | `sys.get_int_max_str_digits()` = 4300 default; the plan's 3572/831 pair is a *function of* this, not a constant |
| P-10 | D2: a negative `Length` is constructible | premise | ✅ TRUE | `0x1000 - 0x2000` = `-4096` |
| P-11 | D2: bare hex is forgeable as a decimal numeral | premise | ✅ TRUE | `f'{int("9"*3572,16):X}'` → `'9'*3572`, `.isdigit()` is `True`, length 3572 |
| P-12 | D2: the two sites take **disjoint** inputs, so one fixture cannot reach both | premise | ✅ TRUE | `_modifications_lines` reads `result.change_summaries[].entries` (`:1071-1075`); `_checklist_lines` reads `result.check_results[].entries` (`:1272`). No shared source |
| P-13 | F4: emitted bytes reach ~208 MB vs a declared 2 MiB | premise | ✅ TRUE | module's own comment `:167-171` states `~100 000 rows → ~208 MB, ~99× the 2 MiB budget`; `REPORT_MAX_TOTAL_BYTES = 2_097_152` `:183`. Measured emitted marginal **92.0 B/entry** (mods) / **78.0 B/entry** (chk) at run=8 — see §2 |
| **P-14** | **OB-4 costs a flat `988 B/entry` across the two functions** | premise | ❌ **FALSE** | **Measured 140.1 B/entry (mods) / 126.1 B/entry (chk) at an 8-byte run.** The cost is **linear in run length** — see §2. 988 B/entry is reproduced only at a ~149-byte run |
| P-15 | batch-65's `_addendum_lines` shape transfers to these two producers | hypothesis | ⚠️ **TRUE WITH A NAMED ADAPTATION** | See §3 — the admission-counter/capped-list/keep-counting core transfers; the "format only after the membership test" step has no analogue here, and cardinality alone is insufficient (§2) |
| P-16 | Neither target is in the engine-frozen set | premise | ✅ TRUE | frozen set is `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`. `tui/services/report_service.py` is in none |
| P-17 | No test references either target function by name | premise | ✅ TRUE | `grep -rln "_modifications_lines\|_checklist_lines" tests/` → **0 files**. Both are reachable only through `generate_project_report`, so black-box ATs are the natural form here, not a concession |

**Blocking verdicts:** P-14 FALSE. Disposition in §2 — it **enlarges** the requirement (C-43: a successful
challenge makes the requirement more complete, never smaller) by adding a second bounding axis.

---

## 2. M-1 / M-2 — the OB-4 cost is linear in byte-run length (P-14 FALSE)

**Method.** Build each producer's real input at two entry counts, measure the resident cost of the
`lines` list it returns (`sys.getsizeof` of the list + every string), and take
`Δresident / ΔN`. Taking a *difference* cancels the fixed heading cost, which a single-point average
would fold in. Run at three counts to confirm linearity in N before reading a marginal off it.

### M-1 — marginal at an 8-byte run

| fn | N | resident B | emitted B | lines |
|---|---|---|---|---|
| `_modifications_lines` | 1000 | 140,049 | 90,993 | 1005 |
| `_modifications_lines` | 2000 | 279,377 | 182,993 | 2005 |
| `_modifications_lines` | 4000 | 560,241 | 366,993 | 4005 |
| `_checklist_lines` | 1000 | 127,376 | 78,160 | 1009 |
| `_checklist_lines` | 2000 | 252,704 | 156,160 | 2009 |
| `_checklist_lines` | 4000 | 505,568 | 312,160 | 4009 |

→ **marginal resident 140.1 B/entry (mods) · 126.1 B/entry (chk)**; emitted 92.0 / 78.0 B/entry.
Linear in N (the three points are collinear to <0.5%).

### M-2 — sweep the byte-run length, N=500

| run (bytes/entry) | mods B/entry | chk B/entry |
|---|---|---|
| 1 | 98.3 | 85.3 |
| 8 | 140.3 | 127.3 |
| 32 | 285.3 | 272.3 |
| 128 | 862.3 | 849.3 |
| 512 | 3 166.3 | 3 153.3 |
| 2048 | 12 383.3 | 12 370.3 |

**The relation is `cost ≈ 92 + 6·run` bytes** — 6 B of rendered row per byte of run, because
`_format_bytes` renders `"%02X "` (3 chars) per byte and each row carries **two** such cells
(`before`+`after` / `expected`+`actual`).

Reproducing the backlog's figure: `run=150 → 994.3 B/entry`. **988 B/entry is the value at a ~149-byte
run, not a constant.**

### The consequence — cardinality alone is not a bound

- `_format_bytes` (`:538-556`) is `" ".join(f"{value:02X}" for value in values)` — **no limit
  parameter, no truncation**. `REPORT_CELL_CHARS = 512` is applied via `md_safe` to the **linkage and
  symbol** cells only; the byte cells never pass through it.
- The upstream per-entry run cap is `MF_RUN_LENGTH_CEILING = 1_048_576` (`changes/io.py:232`) — 1 MiB.

Measured cell growth, and the extrapolation to that ceiling:

```
run=  1024 bytes -> _format_bytes cell =       3,071 chars
run= 65536 bytes -> _format_bytes cell =     196,607 chars
at the 1 MiB ceiling: ONE before-cell   =   3,145,727 chars
one ROW (before + after)                =   6,291,454 chars  = ~6 MiB
```

**A single admitted row can therefore cost ~6 MiB.** A 200-row cap in the style of
`MAX_REPORT_ISSUES_PER_VARIANT` would bound the table at ~1.2 GB — still unbounded for the purpose.

> **Design ruling D-1 (autonomous, flagged inline).** The producer bound is **two-axis**:
> **(a) cardinality** — cap admitted rows, with an admission counter and a truncation notice naming
> what was cut (the batch-65 shape); **(b) per-row width** — bound the rendered byte cells so one row
> cannot be arbitrarily large. Axis (b) is **not** in the plan's Inc-1/Inc-2 sketch and is added on
> this measurement. Without it the batch would ship a cap that demonstrably does not bound the
> quantity it claims to bound — the exact "vacuous acceptance" failure mode this area is on record for.
> Axis (b) is a **rendered-output change**, so it moves goldens; that is measured before Inc-1, not
> predicted (C-39).

---

## 3. P-15 — how much of batch-65's shape actually transfers

`_addendum_lines` (`:1903-2066`) has four separable mechanisms. They do not all transfer:

| Mechanism | Transfers? | Why |
|---|---|---|
| Ordered hit list + **admission counters**, cap applied *at admission* so the list never grows past it (`_AddendumRegionHits.admit`) | ✅ **yes** | Directly applicable; this is the cardinality bound (axis a) |
| **Traversal is not terminated on saturation** — keep counting so the notice can state the true dropped count and the affected variants | ✅ **yes** | Same requirement here: the notice must name what was cut |
| One **truncation notice** naming what was dropped (`_addendum_truncation_notice`) | ✅ **yes** | Same requirement |
| **Format only *after* the membership test** — a candidate matching no region is never formatted | ❌ **no analogue** | The addendum has a region-membership discriminator. These two producers have **no** such test: every entry is a row by definition. The optional `report_filter` is the nearest thing, and it is already applied — though `_modifications_lines` currently materialises `kept` as a **second** full list (`:1080-1082`) before formatting, which this batch can fuse into the single pass |

**Verdict: TRUE with a named adaptation.** The core transfers; the discriminator step does not, and
axis (b) (per-row width) is a *new* requirement with no batch-65 precedent, because the addendum's hit
lines are short fixed-shape strings whose cost does not depend on a byte run.

**Additional finding, `_modifications_lines` vs `_checklist_lines` are not symmetric:**

- `_modifications_lines` materialises **two** intermediate full lists — `entries` (`:1071-1075`, a
  flattening comprehension over all change summaries) and `kept` (`:1080-1082`) — *before* any
  formatting. Both are OB-4 residency in addition to `lines`.
- `_checklist_lines` materialises **neither**: it iterates `result.check_results` then `check.entries`
  directly (`:1254`, `:1272`) and its `total`/`kept` counts are generator `sum(...)`s (`:1244-1250`).
  Its only unbounded residency is `lines` itself.

So the two increments are **not** copies of each other. Treating them as one templated change is the
mistake available here.

---

## 4. M-3 — golden blast radius, EXECUTED (C-39: the gate's own number is run, not predicted)

Full golden inventory and the widest byte cell each contains:

| golden | `| 0x…` rows | widest byte cell |
|---|---|---|
| `batch35/at054b-before-after-report.md` | 2 | 2 chars (1 byte) |
| `batch35/at055b-project-report.md` | 1 | 2 chars (1 byte) |
| `batch64/addendum-below-bound.md` | **415** | 2 chars (1 byte) |
| `batch71/ac6-unscoped-flow-report.md` | 0 | — |
| `batch35/at054b-before-after-report.html` | 0 | — |

**Axis (b), per-row width — blast radius ZERO.** The widest byte cell in *any* golden is **2 chars =
1 byte**. No width bound at any plausible value can drift a golden.

**Axis (a), cardinality — blast radius is NOT zero, and it pins the cap choice.** Attributing the 415
rows to their section:

```
rows per section in tests/goldens/batch64/addendum-below-bound.md:
    415  <- Modifications
```

Consumed by `tests/test_report_addendum_bound.py:793`. So:

| cap value for `_modifications_lines` | goldens drifted |
|---|---|
| **< 415** (e.g. mirroring `MAX_REPORT_ISSUES_PER_VARIANT = 200`) | **1** — `batch64/addendum-below-bound.md` must be deliberately re-baselined |
| **≥ 415** | **0** |

> **This is why the number is executed and not picked.** The plan's Inc-1 sketch says "mirror
> `MAX_REPORT_ISSUES_PER_VARIANT`", and that constant is **200** — which silently re-baselines a
> byte-identity golden belonging to a *different* batch, testing a *different* bound. batch-65's
> cited-as-exemplary result was **0 goldens re-baselined**; taking 200 without measuring would have
> spent that property without noticing. **Decision deferred to Phase 1 as an option table (D-2).**

## 5. What is measured but NOT yet decided (carried into Phase 1)

- **D-2 — the cardinality cap value**, per the table above. A cap of 200 and a cap of 500 are equally
  `O(1)` against the 100 000-entry DoS case; they differ only in whether an unrelated golden moves.
- **D-3 — the per-row width bound value** for axis (b), and its notice form. Zero golden risk, but the
  truncation must be *visible in the document* (the module's own convention: "explicit beats silent").
- Whether axis (b) belongs to D2's fix or stands alone. The D2 `Length` column and the byte cells are
  different columns of the same rows, and D2's fix is a *format* change while axis (b) is a *bound*.

---

## 5. Reproduction

Probes: `m1_marginal.py`, `m2_runlen.py` (session scratchpad — **not** committed; they build fixtures
via the real `ChangeSummaryEntry` / `CheckRunEntry` / `VariantExecutionResult` constructors and import
the private producers directly).

```bash
PYTHONPATH=<repo-root> python m1_marginal.py
PYTHONPATH=<repo-root> python m2_runlen.py
```

`s19_app` is installed nowhere and resolves from `sys.path[0] == cwd`, so a probe run from another
directory needs `PYTHONPATH` explicitly (batch-72 recorded the same trap).
