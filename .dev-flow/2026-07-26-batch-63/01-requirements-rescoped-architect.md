# batch-63 (RE-SCOPED) — Phase-1 requirements: HLR / LLR / Acceptance

**Author:** architect lane · **Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main`
**Inputs (in precedence order):** `00b-measurements-rescoped.md` (C-39 pre-execution transcript —
**authoritative**) > `01-requirements-rescoped.md` (operator scope ruling) > `REQUIREMENTS.md` /
`CLAUDE.md` / `PROJECT_RULES.md`.
**Artifact language:** English. **Phase-1 constraint honoured: zero production source edits.**

---

## 1. BLUF

**Three requirements, one per already-live defect, none of which bounds the report document:**

| id | story | one-line requirement |
|---|---|---|
| **R-TUI-095** | US-B63-D1 | The declared-region addendum **bounds what it materialises AND what it traverses**, per region, and never states a total it did not compute. |
| **R-TUI-096** | US-B63-D2 | Every address-derived integer the report renders in **decimal** renders as *some* string for every schema-legal address — the report never raises on a value its own parser accepts. |
| **R-TUI-097** | US-B63-D3 | Exactly **one** encoder turns a report's lines into the bytes written, and the `_ByteBudget` accounting is a proven **upper bound** on those bytes on every platform. |

**The single most consequential ruling: D3's acceptance is keyed on the SEAM, not on the newline.**

`00b` M-5 established that CI is `ubuntu-latest` (`tui-ci.yml:25`, `:61`, `snapshot-regen.yml:23`),
where the *unpatched* writer already emits LF — so any assertion of the form "the written file
contains no CR" is **GREEN pre-fix on the platform the merge gate runs on**. I executed both
candidate assertion shapes in two `git archive` arms and confirmed it:

```
=== arm A (shipped) | os.linesep='\r\n' ===
  shape 1  'no CR on disk' : bytes=2428  CR_present=True  -> assertion is RED on this host
  shape 2  'single seam'   : module exposes NO document encoder -> assertion RED (cannot bind) on EVERY platform
```

Shape 1 is a Windows-only RED. **Shape 2 — monkeypatch the shared encoder, assert the written file
follows — is RED pre-fix on every platform, because the shipped writer re-joins the lines itself and
there is no encoder to bind.** That is why R-TUI-097 is written as a *single-seam* requirement and
not as a *newline* requirement: the seam is what makes the defect testable where the gate runs.

Second-most consequential: **none of the three closes M-2.** R is unbounded (§5.5), so the addendum
stays linear in a manifest-fed axis; the `> TRUNCATED … (report size cap: N bytes)` marker still
asserts a bound the document violates. The PR text states that plainly (obligation OB-1, §9).

---

## 2. Identifier allocation and why each range is free

| namespace | allocated | freeness evidence (executed) |
|---|---|---|
| Stories | `US-B63-D1/D2/D3` | fixed by the orchestrator registry |
| Requirements | `R-TUI-095/096/097` | highest tracked id is `R-TUI-088`; `git grep -ho "R-TUI-[0-9]\+" -- . ':(exclude).dev-flow' \| sort -u -V` → …086 087 088. `089..094` left RESERVED for batch-64 per the registry. |
| HLR parents | **`HLR-100`, `HLR-101`, `HLR-102`** | Tracked HLR ids run 001…084 then **095…099** (batch-62, `REQUIREMENTS.md:4797`). A repo-wide grep *including* `.dev-flow` for `HLR-[0-9]{3,}` / `LLR-[0-9]{3,}` returns **nothing at or above 100**. 100–102 are the first triple free in **both** the HLR and LLR namespaces — which matters because this project pairs them (batch-62 used HLR-095…099 *and* LLR-095…099). |
| LLR children | `LLR-100.1…`, `LLR-101.1…`, `LLR-102.1…` | same grep; `LLR-097` is batch-62's (`tests/test_report_field_census.py:398`), `LLR-094` is batch-52's. Nothing ≥ 100. |
| Acceptance | `AT-164` … `AT-175` | highest tracked is `AT-163` (batch-62, `tests/test_report_symbol_escape.py`). Allocation in §7. |
| Test cases | `TC-440` … `TC-479` | referenced only; **content owned by the qa-reviewer lane**. Split proposed in §7. |

`report_service.py` and `flow_report_service.py` are **NOT engine-frozen** — verified against both
guards: `tests/test_engine_unchanged.py:120-130` (`_ENGINE_PATHS`) and
`tests/test_tui_directionb.py:5443-5454` (`_ENGINE_PATHS`) list only `core.py`, `hexfile.py`,
`range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`.
`grep -c "report_service" tests/test_engine_unchanged.py` → **0**.

---

## 3. Story US-B63-D1 — the declared-region addendum exhausts memory before it emits anything

> **As** an operator generating a project report over a project with declared regions,
> **I want** the addendum to cost a bounded amount of memory and time regardless of how many change
> entries, variants, or regions the project carries,
> **so that** report generation cannot hang or exhaust the host on input the tool itself accepted.

### 3.1 The defect, on disk

`_addendum_lines` (`s19_app/tui/services/report_service.py:1467`) opens a fresh
`hits: List[str] = []` per region (`:1513`) and appends one **fully formatted** string per
(region × variant × entry) match at `:1518`, `:1524`, `:1532`, then `lines.extend(hits …)` at
`:1537`. Both `hits` and the accumulating `lines` are resident, and the whole cost is paid **before
`generate_project_report`'s single `write_text` at `:1682`** — so no output cap can reach it. `00b`
M-4 confirmed O(R×V×E) by execution on all three axes independently at 87–94 B resident per hit; my
P4 (§6.4) re-measured **89.4 B/hit** and ×3.99 / ×4.01 growth in E.

`_addendum_lines` has **zero direct tests** (`00b` C-26 reverse census).

### 3.2 HLR-100

> **HLR-100 — Bounded declared-region addendum.**
> The declared-region addendum **shall** materialise, per declared region, at most
> `MAX_ADDENDUM_HITS_PER_REGION` hit lines, and **shall** cease traversing that region's candidate
> entries once the cap is reached, so that the addendum's resident cost and its traversal cost are
> both independent of the per-variant entry count and of the variant count. When a region's scan is
> capped, the addendum **shall** state that the listing is incomplete without asserting a total the
> function did not compute.

### 3.3 LLRs

> **LLR-100.1 — Per-region materialisation cap.**
> `_addendum_lines` **shall** append at most `MAX_ADDENDUM_HITS_PER_REGION` entries to a region's
> hit list. The cap **shall** be a module-level constant in
> `s19_app/tui/services/report_service.py`, read at call time so tests can shrink it — the same
> convention `REPORT_MAX_TOTAL_BYTES` already follows (`report_service.py:117-122`).

> **LLR-100.2 — Bounded traversal.**
> On reaching the cap for a region, `_addendum_lines` **shall** stop iterating that region's
> remaining variants, change summaries, check results, entries and issues. Bounding output alone
> **shall not** be treated as satisfying LLR-100.2.

> **LLR-100.3 — Honest truncation notice.**
> When and only when a region's scan was capped, `_addendum_lines` **shall** emit a notice under
> that region naming `MAX_ADDENDUM_HITS_PER_REGION` and stating that the region has **at least**
> that many matches. The notice **shall not** contain a total match count, because LLR-100.2 makes
> that number uncomputed.

> **LLR-100.4 — In-domain byte-identity.**
> For any input whose per-region match count does not exceed `MAX_ADDENDUM_HITS_PER_REGION`, the
> addendum **shall** be byte-identical to the pre-batch output: same lines, same order, no notice.

### 3.4 Acceptance — US-B63-D1

**Observable outcome (black-box).** An operator generates a project report on a project whose
declared region matches far more entries than the cap. The report is produced; the addendum lists
the cap's worth of hits and then says, in the document, that the region has *at least* that many
matches and no more were listed. Report generation's peak memory and wall time do not grow when the
project's change entries or variants are multiplied. On any project whose regions match fewer
entries than the cap, the report file is **byte-identical** to the one the previous release produced.

**Shipped surface producing it.** `generate_project_report`
(`s19_app/tui/services/report_service.py:1542`) → `_addendum_lines` (`:1467`) → the report `.md`
under `<project_dir>/reports/`. No new UI, no new option, no new file format.

| AT | what it observes | bites because |
|---|---|---|
| **AT-164** | Peak resident memory of `generate_project_report` does not grow when the per-variant entry count is multiplied, at fixed regions and variants. | Pre-fix this grows ×4 for a ×4 entry count (§6.4, executed). |
| **AT-165** | The number of hit lines rendered under one region never exceeds `MAX_ADDENDUM_HITS_PER_REGION` — the AT names the **constant**, never a literal. | Pre-fix the count equals the match count, which is unbounded. |
| **AT-166** | When capped, the region's notice names `MAX_ADDENDUM_HITS_PER_REGION` and contains **no** total match count; when not capped, no notice is present. | A notice that quoted a total would prove traversal was not bounded (LLR-100.2). This is the AT that makes LLR-100.2 non-vacuous from black-box observation alone. |
| **AT-167** | For an input with fewer matches per region than the cap, the generated report is byte-for-byte identical to the arm-A (pre-fix) report. | Executed in-domain maximum is **2** hits/region (§6.3), so this arm must be green with a 100× margin. |

---

## 4. Story US-B63-D2 — a schema-legal address crashes report generation

> **As** an operator generating a project report over a change file the tool accepted,
> **I want** the report to be produced,
> **so that** an address my own parser called valid cannot deny me the evidentiary document.

### 4.1 The defect, on disk

`_ADDRESS_RE = re.compile(r"^0x[0-9A-Fa-f]+$")` (`s19_app/tui/changes/io.py:235`) places **no digit
limit** on an address, and `_parse_address` (`io.py:918`) accepts it. The report then renders the
`Length` column as a **decimal** interpolation of `entry.address_end - entry.address_start`, which
raises once the decimal form exceeds `sys.get_int_max_str_digits()`.

**The crash-site input set is derived, not hand-listed (C-31).** Every decimal interpolation of an
address-derived integer in the two budgeted report modules:

```
$ grep -rn "{entry.address\|{issue.address\|{region.start\|{region.end\|{low\|{high" \
    --include="*.py" s19_app/tui/services/report_service.py \
                     s19_app/tui/services/flow_report_service.py | grep -v ":X}\|:08X}\|:02X}\|#"
s19_app/tui/services/report_service.py:996:            f"| {entry.address_end - entry.address_start} "
s19_app/tui/services/report_service.py:1171:                f"| {entry.address_end - entry.address_start} "
s19_app/tui/services/report_service.py:1460:            f" ({low_conf[label]} low-confidence)" if low_conf[label] else ""
```

**The set has exactly two members.** `:996` is in `_modifications_lines` (`:923`); **the "checklist
twin" is `report_service.py:1171`, in `_checklist_lines` (`:1095`)** — named, as asked. `:1460` is a
window counter bounded by `REPORT_MAX_REGIONS_PER_VARIANT` (`:77`), not address-derived, and is
excluded on that evidence rather than by taste. The address *cells* are `0x{…:08X}` / `0x{…:X}` and
are exempt (hex conversion has no digit limit — executed, §6.2).

### 4.2 HLR-101

> **HLR-101 — The report renders every address its parser accepts.**
> For every address value `_parse_address` accepts, `generate_project_report` **shall** produce a
> report file rather than raise. Every site that renders an address-derived integer in decimal
> **shall** render, for such a value, a string; and the rendering **shall** be byte-identical to the
> pre-batch rendering for every value whose decimal form the interpreter can produce.

### 4.3 LLRs

> **LLR-101.1 — Guarded decimal rendering.**
> `report_service.py:996` and `report_service.py:1171` **shall** obtain the `Length` cell from a
> single shared helper. That helper **shall** return the decimal form when the interpreter can
> produce it and a hexadecimal form otherwise.

> **LLR-101.2 — The predicate is the conversion.**
> The helper's fallback **shall** be selected by attempting the decimal conversion and catching its
> `ValueError`, **not** by comparing the value against a digit-count estimate or a hard-coded
> `4300`. `sys.get_int_max_str_digits()` is interpreter-configurable and a bit-length estimate is
> approximate exactly at the boundary; a predicate that tests something other than what its label
> claims is the defect class this batch exists to fight.

> **LLR-101.3 — In-domain byte-identity.**
> For every length whose decimal form the interpreter can produce, the emitted `Length` cell
> **shall** be byte-identical to the pre-batch cell. No golden may drift.

> **LLR-101.4 — Fail-closed preserved.**
> `generate_project_report` **shall** retain exactly one write of the report file, positioned after
> all line composition, so that any composition failure continues to leave **no** file in
> `reports/`. The fix **shall not** introduce a partial or incremental write.

### 4.4 Acceptance — US-B63-D2

**Observable outcome (black-box).** An operator loads a change file carrying an address wide enough
that its length has more decimal digits than the interpreter will render, and generates a report.
Today the tool raises `ValueError` and leaves `reports/` empty. After: a report file exists, the
row for that entry is present, and its `Length` cell reads as a hexadecimal value. Every report over
ordinary addresses is unchanged, byte for byte.

**Shipped surface producing it.** The change-file ingest path (`_parse_address`,
`s19_app/tui/changes/io.py:918`) → `generate_project_report` (`report_service.py:1542`) →
`_modifications_lines` (`:923`) / `_checklist_lines` (`:1095`) → the report `.md`.

| AT | what it observes | bites because |
|---|---|---|
| **AT-168** | A change file whose address is **3572** hex digits wide (§6.2) produces a report file; a report is generated and `reports/` contains it. | Pre-fix this raises `ValueError` (`00b` M-3, re-derived §6.2). RED on every platform. |
| **AT-169** | A change file whose address is **3571** hex digits wide produces a report whose `Length` cell is the exact decimal string. | The lower half of the boundary pair. It bites against an over-eager fix that switches the column to hex wholesale — executed to change **9/9** in-domain renderings (§6.2). |
| **AT-170** | The **checklist** table (`_checklist_lines`) is exercised with the same 3572-digit input and behaves identically to the modifications table. | The twin is a separate call site; a fix applied at `:996` only would leave `:1171` raising. |
| **AT-171** | When report composition raises for any reason, `reports/` contains no new file. | Guards LLR-101.4 against a refactor that streams the document. |

---

## 5. Story US-B63-D3 — the byte accounting undercounts the file it is accounting for

> **As** a maintainer relying on `_ByteBudget` to decide what a report emits,
> **I want** the number the allocator charges to be a proven upper bound on the bytes that reach
> disk,
> **so that** a gate keyed on that number cannot pass a document that exceeds its cap.

### 5.1 The defect, on disk

`_line_bytes` (`report_service.py:392`) charges `len(line.encode("utf-8")) + 1` per line, so an
allocator that consumes it holds `Σlen + N`. The document is `"\n".join(lines)` = `Σlen + (N−1)`.
The writers are text-mode `write_text` (`report_service.py:1682`; `flow_report_service.py:456`), so
on Windows the file is `Σlen + 2(N−1)` and the accounting undercounts by **N−2** — `00b` M-1/M-1b,
7/7 compositions. Independently reproduced here on a real generated report (§6.5): accounted 2359,
on disk 2428, N = 71, delta 69 = N−2.

### 5.2 RULING D3-A — the writer and the accounting share ONE encoder

**"Pin the writer" is insufficient, and the reason is a test-visibility problem, not an arithmetic
one.** `00b` M-5 showed pinning leaves the accounting 1 byte *over* (the safe direction) — fine —
but also that CI runs `ubuntu-latest`, where the unpatched writer already emits LF, so a
newline-keyed assertion is green before the fix. I executed both candidate assertion shapes in two
`git archive` arms (§6.5):

- **Shape 1, "no CR on disk"** — RED in arm A on Windows, **GREEN in arm A on Linux**. It cannot
  fail on the merge gate. Same shape as batch-61's "`tui-ci` is BLIND to snapshot drift".
- **Shape 2, "single seam"** — monkeypatch the module's document encoder and assert the written file
  follows. In arm A the module **exposes no document encoder at all**, so the assertion cannot even
  bind: **RED on every platform, including CI.**

**Ruling: one shared encoder for the writer and the accounting, with the acceptance keyed on the
seam.** (The normative form of this ruling is HLR-102 / LLR-102.1 below; this paragraph is
informative.) The newline assertion is retained as a *supplementary* Windows-only arm and is
labelled as not verified by the merge gate, rather than being allowed to imply CI covers D3.

### 5.3 RULING D3-B — the platform-independent invariant

`00b` proposed `len(LF.join(lines).encode()) == _line_bytes(lines) - 1`. **I executed it over a
derived input set and it is false at N = 0** (§6.1): `_line_bytes([])` is 0 and the encoded document
is 0 bytes, so `0 == -1` fails. N = 0 is reachable — `emit`/`put` take a `Sequence[str]` and
`_declaration_error_lines`-style helpers return early.

**The invariant the acceptance uses instead — executed 7/7 including N = 0:**

```
_line_bytes(lines) >= len("\n".join(lines).encode("utf-8"))       for all lines
```

It is universal, platform-independent by construction, and states the property that actually matters
to a gate: **the accounting is an upper bound, never an undercount.** The residual 1-byte
conservatism (equality only at N = 0) is stated in the requirement rather than papered over.

### 5.4 RULING D3-C — `flow_report_service` is IN scope

**Recommendation: fix both modules in this batch. Reasoning, with evidence:**

1. **They share the primitive, not merely a pattern.** `flow_report_service.py:69-74` imports
   `_ByteBudget` and `_line_bytes` **from** `report_service`. Fixing one writer leaves a single
   shared allocator with one pinned consumer and one unpinned one — precisely the divergence
   ruling D3-A exists to prevent. A "single encoder" requirement that skips a caller of that
   encoder's own budget is self-contradicting.
2. **The flow module's use is more load-bearing.** `report_service`'s `fits()` gates hexdump blocks
   only (`:1347`); `flow_report_service`'s `put()` at `:310` **drops a whole section and records it
   as truncated** when `fits()` says no (`:308-315`). An undercounting allocator there decides
   *emission*, not just a cap.
3. **The diff is mechanical and measured neutral.** Arm B patched both writers and ran the
   C-31-derived observer set — **155 passed in both arms** (§6.5), including
   `tests/test_flow_report_service.py`, which closes `00b` M-2's own self-flagged omission.

**Cost acknowledged, not dismissed:** batch-62 deliberately restored `flow_report_service.py`
byte-for-byte to `main` after withdrawing D-11, so re-opening it is not free. But that restoration
was about a withdrawn *redaction* control, not a freeze — the file is in neither guard's
`_ENGINE_PATHS` (§2). The cost is a re-review of one import line and one writer line.

**`diff_report_service` is OUT of scope, explicitly.** It writes reports at `:1393` and `:2063` with
the same text-mode join, but `grep -c "_ByteBudget\|_line_bytes" s19_app/tui/services/diff_report_service.py`
→ **0**: it has no accounting to be wrong against. Normalising its newlines would touch two more
writers and their goldens to close zero defects. Carried to `.dev-flow/BACKLOG.md` as a consistency
follow-up.

### 5.5 RULING D3-D / D1-D — what these requirements do NOT close

`options.declared_regions` has **no cardinality cap anywhere**. Derived, not asserted: every
`declared_regions` / `DECLARED_REGION` reference in `s19_app/` was enumerated; the only cap is
`DECLARED_REGION_NAME_MAX = 80` (`s19_app/tui/services/report_addendum.py:26`), which bounds a
region's **name**, not the region **count**, and `_parse_manifest_declared_regions`
(`variant_execution_service.py:295`) contains no `len(` / slice / `MAX` guard.

So after R-TUI-095 the addendum costs `R × MAX_ADDENDUM_HITS_PER_REGION × ~89 B`, linear in a
manifest-fed axis. That is a reduction of a **product of three file-fed axes** to **one**, measured
at ×2560 for R = V = 64 (§6.4) — a real fix, and not a document bound. **R-TUI-095 does not close
M-2 and the artifact says so** (obligation OB-1, §9).

### 5.6 HLR-102

> **HLR-102 — Single document encoder; accounting is an upper bound.**
> Every report writer that consults a `_ByteBudget` **shall** obtain the bytes it writes from one
> shared encoder, and **shall not** perform its own line-joining or encoding. For every line
> sequence, the byte count `_line_bytes` charges **shall** be greater than or equal to the length of
> the bytes that encoder produces, and the size of the file on disk **shall** equal that length on
> every platform.

### 5.7 LLRs

> **LLR-102.1 — One encoder.**
> `s19_app/tui/services/report_service.py` **shall** expose a single function that converts a
> report's line sequence to the `bytes` written to disk. `generate_project_report`
> (`report_service.py:1542`) and `write_flow_report` (`flow_report_service.py:408`) **shall** both
> obtain their written bytes from that function and **shall not** call `write_text`.

> **LLR-102.2 — Upper-bound accounting.**
> `_line_bytes(lines) >= len(<encoder>(lines))` **shall** hold for every line sequence, including
> the empty sequence. The accounting **shall not** undercount on any platform.

> **LLR-102.3 — Platform-independent file size.**
> The size of a written report **shall** equal the length of the bytes the encoder produced,
> independent of `os.linesep`.

> **LLR-102.4 — Golden neutrality.**
> The change **shall not** alter any stored golden or snapshot. `canonical_report_bytes`
> (`tests/conftest.py:1009`) already normalises `\r\n` → `\n`, so the fix is observable to no
> existing assertion — measured in both arms (§6.5), not assumed.

### 5.8 Acceptance — US-B63-D3

**Observable outcome (black-box).** A generated report is the same size on Windows and on Linux for
the same input, and that size never exceeds the number of bytes the budget charged for it. A
maintainer who replaces the module's document encoder sees the written file change — there is one
place bytes are made. No existing report golden moves.

**Shipped surface producing it.** `generate_project_report` (`report_service.py:1542`) and
`write_flow_report` (`flow_report_service.py:408`) → the `.md` files under
`<project_dir>/reports/`.

| AT | what it observes | bites because |
|---|---|---|
| **AT-172** | Replacing the shared encoder changes the bytes `generate_project_report` writes. | Pre-fix the module exposes no encoder to replace — **RED on every platform including CI** (§6.5, executed in both arms). This is the AT the merge gate actually runs. |
| **AT-173** | The same, for `write_flow_report`. | Enforces ruling D3-C. `flow_report_service` gates *emission* on the shared budget (`:310`). |
| **AT-174** | `_line_bytes(lines) >= len(<encoder>(lines))` over a derived line-sequence set that **includes the empty sequence**. | The N = 0 case falsifies `00b`'s proposed `== _line_bytes - 1` form (§6.1, executed). Platform-independent. |
| **AT-175** | *Supplementary, Windows-only:* on a host where `os.linesep == "\r\n"`, a written report contains no `\r`. | **Explicitly labelled as NOT verified by the merge gate** — pre-fix it is green on `ubuntu-latest` (`tui-ci.yml:25`, `:61`; `snapshot-regen.yml:23`). It is recorded so the Windows behaviour is pinned for a developer running locally, not so the batch can imply CI covers it. |

---

## 6. Executed verification — every threshold this artifact introduces

Per **C-39**: predicted thresholds false-fail correct implementations as readily as they pass wrong
ones. Every number below is output. Probe discipline: bounded fixtures (E ≤ 8 000; the 200 000-hit /
50 MB ceiling was never approached), counterfactuals in `git archive` exports at the short root
`C:/Users/jjgh8/AppData/Local/Temp/claude/b63/{arch,archb}`, patch scripts written to a file and
invoked by path, temp trees deleted (§10).

### 6.1 D3 — the invariant, over a C-31-derived input set

Input-set derivation: every `_line_bytes` call site was enumerated —
`flow_report_service.py:310`, `:313`; `report_service.py:1312`, `:1347`, `:1638` — all of which pass
a `Sequence[str]` batch. The cardinalities the type admits are N = 0 and N ≥ 1; both are exercised.

```
host platform      : Windows
os.linesep         : '\r\n'
sys.version        : 3.14.4
int_max_str_digits : 4300

case                             N  _line_bytes  len(encoded)   delta  acc>=enc  acc-1==enc
N=0  (empty batch)               0            0             0       0      True       False
N=1  (single line)               1            9             8       1      True        True
N=2                              2           10             9       1      True        True
N=3 ascii                        3            9             8       1      True        True
N=3 non-ascii (2B/char)          3           15            14       1      True        True
N=5 with empties                 5            8             7       1      True        True
N=200 synthetic                200         4090          4089       1      True        True

UNIVERSAL  _line_bytes(lines) >= len(LF-join.encode)  holds on: 7 / 7 | violations: []
PROPOSED-IN-00b  _line_bytes(lines) - 1 == len(...)   holds on: 6 / 7 | violations: ['N=0  (empty batch)']
```

**Correction contributed to `00b`:** the M-5 invariant is false at N = 0. AT-174 uses the `>=` form.

### 6.2 D2 — the boundary, re-derived, and the three candidate fixes evaluated at it

Re-derived from scratch rather than copied (`00b` states 3572; this is an independent execution):

```
sys.get_int_max_str_digits() = 4300
   3570 hex digits -> hex OK | decimal OK (4299 digits)
   3571 hex digits -> hex OK | decimal OK (4300 digits)
   3572 hex digits -> hex OK | decimal RAISES (Exceeds the limit (4300 digits) for integer string conversion; ...)
  --> first raising width: 3572 hex digits
```

```
=== candidate fix shapes at the boundary pair ===
shape                         3571 (survives)      3572 (raises)
(a) hex column                    ok len=3573        ok len=3574
(b) cap rendered width              ok len=32             RAISES
(d) guarded decimal               ok len=4300        ok len=3574

=== (d) byte-identity vs today, over in-domain lengths ===
  --> in-domain renderings changed by (d): 0 / 9
=== (a) byte-identity vs today, over the same in-domain lengths ===
  --> in-domain renderings changed by (a): 9 / 9
```

**Ruling D2-A, decided on this output, not on preference:**

- **(b) "cap the rendered width" is not a fix — it still raises.** `f"{n}"[:cap]` evaluates the
  conversion before slicing. Eliminated by execution.
- **(a) "render the column in hex" changes 9/9 in-domain renderings.** The report is an evidentiary
  document correlating symbols to addresses; the reader compares `Length` against the `Before` /
  `After` byte runs, which are counts. Converting every length in every report to hex, forever, to
  defend against a 3572-hex-digit address is a global readability regression plus total golden
  churn, in exchange for closing one pathological input.
- **(d) guarded decimal changes 0/9 in-domain renderings and survives 3572.** Chosen.

**The boundary pair bites both ways under (d):** 3571 → the decimal cell is byte-identical to today
(AT-169); 3572 → a report is produced where today none is (AT-168).

**Stated limitation, not hidden:** (d) converts a *crash* into a *large cell* — 4300 chars at 3571
(which the shipped code **already emits today without raising**) and 3574 at 3572. `REPORT_CELL_CHARS`
(`report_service.py:115`) is not applied to the `Length` column today. Bounding that cell is the
document-bounding axis and belongs to **batch-64**; pulling it in here is the scope creep the
re-scope ruling exists to prevent.

### 6.3 D1 — the in-domain maximum, executed over the derived corpus

Corpus derivation (C-31): `grep -rln "declared_regions\|_addendum_lines" tests/` →
`test_capped_text_area.py`, `test_manifest_writer.py`, `test_report_field_census.py`,
`test_report_service.py`, `test_tui_report_seam.py`. The real `_addendum_lines` was wrapped by a
pytest plugin and the hit lines under each `### <region>` heading counted.

```
$ python -m pytest -q -p p3_plugin -s tests/test_report_service.py tests/test_tui_report_seam.py \
      tests/test_report_field_census.py tests/test_manifest_writer.py

=== P3 addendum census (in-domain shipped corpus) ===
  _addendum_lines calls observed : 14
  max REGIONS in one call (R)    : 2
  total region renders           : 18
  MAX HITS IN ONE REGION         : 2
  max hits in one whole addendum : 2

116 passed in 111.26s (0:01:51)
```

**Cap value ruling (D1-B): `MAX_ADDENDUM_HITS_PER_REGION = 200`.**
- Executed in-domain maximum is **2**, so 200 carries a **100×** margin — LLR-100.4 / AT-167
  byte-identity is green by measurement, not by hope.
- 200 is not a fresh number: `MAX_REPORT_ISSUES_PER_VARIANT = 200` (`report_service.py:90`) and
  `MAX_REPORT_FINDINGS_PER_BLOCK = 200` (`flow_report_service.py:88`) already exist, and the former's
  own comment states 200 mirrors the latter "deliberately — … a reader comparing the two report
  kinds should not have to learn two numbers". A third per-section cap in the same module at a
  different value would violate a convention the codebase states in prose.
- **C-36:** `MAX_ADDENDUM_HITS_PER_REGION` does not exist on disk —
  `grep -rn "MAX_ADDENDUM" --include="*.py" s19_app/ tests/` → no match. **`NEW — created in
  Phase 3`.** AT-165 / AT-166 quote the constant, never `200`.

### 6.4 D1 — does bounding the scan flatten the cost?

Bounded probe, ceiling E = 8 000 (≤ 8 000 hits; the session's 200 000-hit ceiling was never
approached; nothing written to disk):

```
      E   unbounded peak B   B/hit |   bounded peak B   lines   scanned
    500              44709    89.4 |            17849     200       201
   2000             178177    89.1 |            17849     200       201
   8000             715217    89.4 |            17849     200       201

=== growth in E ===
  E 500->2000 (x4)   unbounded peak x3.99   bounded peak x1.00
  E 2000->8000 (x4)  unbounded peak x4.01   bounded peak x1.00

  measured resident bytes per hit     : 89.4
    at R=V=64 amplification = 7042.14x
  WITH a per-region cap of K=200, hits <= R x K, INDEPENDENT of V and E:
    at R=V=64 hits = 12800 (was 32768000)  -> reduction x2560
```

89.4 B/hit sits inside `00b` M-4's measured 87–94 B/hit band — the carried constant re-derived, not
copied. `scanned = 201` (one past the cap) is the executed evidence that **traversal**, not merely
output, is bounded — the property LLR-100.2 states and AT-166 makes observable.

**`00b` C-5 honoured:** the "~559.7 GB / ~1 283 min" headline is *not* adopted as a threshold here,
because its input triple was never stated and cannot be re-derived. This artifact carries the
measured per-hit constant and the amplification ratios instead, each with its inputs printed.

### 6.5 D3 — two-arm counterfactual and the seam probe

Arm A = `git archive 031ca8d` unmodified. Arm B = the same export with both writers routed through
one `_encode_document`. Observer set **derived**
(`grep -rln "generate_project_report\|write_flow_report\|compose_flow_report" tests/`), which
**includes `tests/test_flow_report_service.py`** — the omission `00b` M-2 flagged against itself.

```
ARM A (baseline, unpatched):  155 passed in 137.10s
ARM B (shared encoder, BOTH writers): 155 passed in 137.31s
```

```
=== arm A (shipped) | os.linesep='\r\n' ===
  shape 1  'no CR on disk' : bytes=2428  CR_present=True  -> assertion is RED on this host
  shape 2  'single seam'   : module exposes NO document encoder -> assertion RED (cannot bind) on EVERY platform
  accounting: _line_bytes=2359  LF-encoded=2358  acc>=enc=True  on_disk=2428  disk<=acc=False
=== arm B (patched) | os.linesep='\r\n' ===
  shape 1  'no CR on disk' : bytes=2358  CR_present=False  -> assertion is GREEN on this host
  shape 2  'single seam'   : file bytes == sentinel -> True  -> assertion is GREEN on this host
  accounting: _line_bytes=2359  LF-encoded=2358  acc>=enc=True  on_disk=2358  disk<=acc=True
```

Three thresholds established by this output:
1. **Golden neutrality is measured for BOTH writers** — 155/155 in both arms. LLR-102.4 is not
   `assumed`.
2. **The N−2 undercount reproduces on a real report:** N = 71 lines, accounted 2359, on disk 2428,
   delta 69 = N − 2. Independent of `00b` M-1b's synthetic grid.
3. **Blast radius = 2 modules.** `grep -rn "write_text(\|write_bytes(" s19_app/tui/services/` returns
   6 writers; cross-checked for accounting, only `report_service.py:1682` and
   `flow_report_service.py:456` consult a `_ByteBudget`. `diff_report_service.py:1393`/`:2063` have
   `grep -c "_ByteBudget\|_line_bytes"` → 0.

### 6.6 CI platform — the reason AT-175 is labelled non-gating

```
$ grep -n "runs-on" .github/workflows/*.yml
.github/workflows/snapshot-regen.yml:23:    runs-on: ubuntu-latest
.github/workflows/tui-ci.yml:25:    runs-on: ubuntu-latest
.github/workflows/tui-ci.yml:61:    runs-on: ubuntu-latest
```

---

## 7. Traceability matrix

**Behavioural chain (US → AT → outcome)**

| US | AT | observable outcome |
|---|---|---|
| US-B63-D1 | AT-164 | Peak memory of report generation is flat in the entry count. |
| US-B63-D1 | AT-165 | No region lists more hits than the cap constant. |
| US-B63-D1 | AT-166 | A capped region says "at least K" and never a total. |
| US-B63-D1 | AT-167 | Ordinary projects produce a byte-identical report. |
| US-B63-D2 | AT-168 | A 3572-hex-digit address yields a report instead of a `ValueError`. |
| US-B63-D2 | AT-169 | A 3571-hex-digit address yields today's exact decimal cell. |
| US-B63-D2 | AT-170 | The checklist table behaves identically to the modifications table. |
| US-B63-D2 | AT-171 | A composition failure leaves no file in `reports/`. |
| US-B63-D3 | AT-172 | Replacing the encoder changes the project report's bytes. |
| US-B63-D3 | AT-173 | Replacing the encoder changes the flow report's bytes. |
| US-B63-D3 | AT-174 | The charged byte count is never below the encoded length, N = 0 included. |
| US-B63-D3 | AT-175 | *(Windows-only, non-gating)* a written report contains no `\r`. |

**Functional chain (US → HLR → LLR → TC-range)**

| US | R-* | HLR | LLR | AT | TC range (qa-reviewer owns content) |
|---|---|---|---|---|---|
| US-B63-D1 | R-TUI-095 | HLR-100 | LLR-100.1 materialisation cap | AT-165 | TC-440 … TC-443 |
| US-B63-D1 | R-TUI-095 | HLR-100 | LLR-100.2 bounded traversal | AT-164, AT-166 | TC-444 … TC-448 |
| US-B63-D1 | R-TUI-095 | HLR-100 | LLR-100.3 honest notice | AT-166 | TC-449 … TC-450 |
| US-B63-D1 | R-TUI-095 | HLR-100 | LLR-100.4 in-domain identity | AT-167 | TC-451 … TC-452 |
| US-B63-D2 | R-TUI-096 | HLR-101 | LLR-101.1 guarded rendering | AT-168, AT-170 | TC-453 … TC-457 |
| US-B63-D2 | R-TUI-096 | HLR-101 | LLR-101.2 predicate = conversion | AT-168 | TC-458 … TC-460 |
| US-B63-D2 | R-TUI-096 | HLR-101 | LLR-101.3 in-domain identity | AT-169 | TC-461 … TC-463 |
| US-B63-D2 | R-TUI-096 | HLR-101 | LLR-101.4 fail-closed | AT-171 | TC-464 … TC-465 |
| US-B63-D3 | R-TUI-097 | HLR-102 | LLR-102.1 one encoder | AT-172, AT-173 | TC-466 … TC-471 |
| US-B63-D3 | R-TUI-097 | HLR-102 | LLR-102.2 upper-bound accounting | AT-174 | TC-472 … TC-475 |
| US-B63-D3 | R-TUI-097 | HLR-102 | LLR-102.3 platform-independent size | AT-172, AT-175 | TC-476 … TC-477 |
| US-B63-D3 | R-TUI-097 | HLR-102 | LLR-102.4 golden neutrality | AT-167, AT-169 | TC-478 … TC-479 |

---

## 8. Proposed increment cut (≤ 5 files each, dependency order)

**Inc-1 — D3, the seam (blocks nothing, unblocks the accounting)**
`s19_app/tui/services/report_service.py` · `s19_app/tui/services/flow_report_service.py` ·
`tests/test_report_service.py` · `tests/test_flow_report_service.py` — **4 files.**
Introduce the single encoder; both writers call it; AT-172/173/174/175. Measured golden-neutral
(§6.5). *First because it is the only change that touches a shared primitive — later increments then
build on a settled seam.*

**Inc-2 — D2, the guarded length (independent of Inc-1)**
`s19_app/tui/services/report_service.py` · `tests/test_report_service.py` ·
`tests/conftest.py` (a wide-address fixture, if the existing generators do not cover it) —
**≤ 3 files.** One helper, two call sites (`:996`, `:1171`); AT-168/169/170/171.

**Inc-3 — D1, the bounded addendum**
`s19_app/tui/services/report_service.py` · `tests/test_report_service.py` ·
`REQUIREMENTS.md` — **3 files.** New constant + cap + break + notice; AT-164/165/166/167.
*Last because it is the only one that adds a document-visible string (the notice), so it should land
against a report whose byte accounting is already correct.*

**Inc-4 — registry + carry**
`REQUIREMENTS.md` (R-TUI-095/096/097 entries, HLR-100…102) · `.dev-flow/BACKLOG.md` (the R-axis,
`diff_report_service` newline consistency, the unbounded `Length` cell) · PR body (OB-1) —
**3 files.**

`pyproject.toml` / `project.toml` are untouched. No frozen-engine path is touched (§2).

---

## 9. Risks, open questions, and everything flagged `assumed`

| id | risk / question | severity | handling |
|---|---|---|---|
| **OB-1** | The batch could be read as closing M-2. It does not: R is unbounded (§5.5) and the `> TRUNCATED … (report size cap: N bytes)` marker (`report_service.py:1355`) still asserts a bound the document violates. | **obligation** | The PR body states plainly that batch-63 closes three defects and **not** the document bound. Non-negotiable — the batch's founding thesis is that a document must not assert what it does not honour. |
| R-1 | D1's cap makes the addendum linear in R, which nothing bounds. | high, accepted | Stated in HLR-100's scope, measured (§6.4), carried to BACKLOG for batch-64. Not silently absorbed. |
| R-2 | D2's fix converts a crash into a ~3.5 KB cell; `REPORT_CELL_CHARS` is not applied to `Length`. | medium, accepted | Pre-existing in-domain (a 4300-char cell renders today without raising). Bounding it is batch-64's axis. Carried. |
| R-3 | AT-175 cannot fail on the merge gate. | medium | Labelled non-gating in its own AT row and in §5.2. AT-172/173/174 carry the gate. **The failure mode this guards against is a reviewer reading a green CI as evidence D3 is covered.** |
| R-4 | Touching `flow_report_service.py` re-opens a file batch-62 deliberately restored byte-for-byte. | medium | Ruled IN with reasoning (§5.4) and measured neutral over the derived observer set including `test_flow_report_service.py` (§6.5). Recommend the security lane re-confirm the file at review. |
| R-5 | `compose_flow_report` (`flow_report_service.py:273`) returns a **`str`**, not lines (`:405`), so the shared encoder's signature has to accommodate both shapes. Arm B used a `str.split("\n")` round-trip, which is exact but inelegant. | low | The exact signature is **deferred to Phase 3**; LLR-102.1 constrains the *property* (one function, both writers call it), not the shape. |
| R-6 | LLR-101.2 mandates catching `ValueError` around a formatting call. A reviewer may read that as a code smell. | low | It is the only predicate that tests what its label claims: `sys.get_int_max_str_digits()` is interpreter-configurable and a bit-length estimate is wrong exactly at the boundary. Reasoning recorded here so review does not re-litigate it blind. |
| **Q-1** | Should the D1 notice count toward `_ByteBudget`? `_addendum_lines` is emitted through `emit` (`report_service.py:1673`) so it already is — no action, but Phase 3 should not add a second accounting path. | open, low | Flagged for Phase 2. |
| **Q-2** | `MAX_ADDENDUM_HITS_PER_REGION = 200` — is per-region the right granularity, versus one budget shared across all regions? Per-region is chosen because a shared budget makes late regions render nothing, which is attacker-selectable first-N truncation (a carried finding). | resolved, recorded | No operator input needed; recorded so the alternative is traceable. |

**Everything this artifact flags rather than asserts:**

- `MAX_ADDENDUM_HITS_PER_REGION` — **`NEW — created in Phase 3`** (C-36; `grep -rn "MAX_ADDENDUM"
  s19_app/ tests/` → no match).
- The shared encoder function name — **`NEW — created in Phase 3`**; arm B used `_encode_document`
  as a placeholder, and no acceptance names it as a literal.
- `_parse_address` is cited at `s19_app/tui/changes/io.py:918` (the `def`), verified by grep;
  `00b` cites `:952` for the same function — a body line, not a contradiction, but the **`:918`**
  figure is the one verified here.

---

## 10. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Constraints stated explicitly | ✓ | §1 (no document bound), §5.5 (R unbounded), §8 (≤5 files/increment), §2 (frozen-set exclusion) |
| 2 | ≥ 2 alternatives considered | ✓ | D2: three fix shapes executed side by side (§6.2 — (b) eliminated *by output*, not argument). D3: two assertion shapes executed in two arms (§6.5). D1: per-region vs shared budget (Q-2). |
| 3 | Recommendation tied to constraints | ✓ | D3-A tied to the CI platform (§6.6); D2-A tied to the report's evidentiary purpose + 9/9 in-domain churn (§6.2); D3-C tied to the shared import `flow_report_service.py:69-74` and the emission gate `:310`. |
| 4 | Risks listed (operational / security / cost / lock-in) | ✓ | §9, nine rows incl. one **obligation** (OB-1) and two accepted-with-carry. |
| 5 | Cost / latency estimated where relevant | ✓ | §6.4 — 89.4 B/hit measured; ×3.99/×4.01 unbounded growth; ×1.00 bounded; ×2560 reduction at R=V=64. §6.5 — 137.10 s vs 137.31 s two-arm suite cost. |
| 6 | Diagram included when flow is non-trivial | ✗ | **Deliberately omitted.** The three defects are point defects in one call chain already given as `file:line` (`:1542` → `:1467`/`:923`/`:1095` → `:1682`). A box diagram would restate the trace at lower fidelity. |
| 7 | What would change the recommendation is stated | ✓ | D3-C flips to "carry `flow_report_service`" if arm B's 155/155 (§6.5) ever regresses. D2-A flips to hex-column if the operator rules the `Length` column should be hex for *readability* reasons — that is a product decision, not one this evidence settles. D1's cap value changes if the in-domain maximum (currently **2**, §6.3) ever approaches 200. |
| 8 | Two-layer requirements: first-class Acceptance block + `AT-NNN` per story, BOTH chains | ✓ | §3.4, §4.4, §5.8 each carry an Acceptance block (observable outcome · shipped surface · AT table). §7 carries **both** matrices: behavioural US→AT→outcome and functional US→HLR→LLR→TC. |
| 9 | `shall` only inside HLR/LLR | ✓ | HLR-100/101/102 and LLR-100.x/101.x/102.x only. Prose uses indicative mood. |
| 10 | C-39: every introduced threshold executed | ✓ | §6.1 (N=0 falsification) · §6.2 (3571/3572 re-derived; 3 fix shapes) · §6.3 (in-domain max = **2**) · §6.4 (89.4 B/hit; ×1.00 flat) · §6.5 (155/155 both arms; N−2 on a real report; seam RED/GREEN) · §6.6 (CI platform). |
| 11 | C-36: every literal an acceptance names resolves on disk or is flagged NEW | ✓ | `MAX_REPORT_ISSUES_PER_VARIANT` `report_service.py:90` · `MAX_REPORT_FINDINGS_PER_BLOCK` `flow_report_service.py:88` · `REPORT_CELL_CHARS` `:115` · `REPORT_MAX_TOTAL_BYTES` `:122` · `REPORT_MAX_REGIONS_PER_VARIANT` `:77` · `DECLARED_REGION_NAME_MAX` `report_addendum.py:26` · `canonical_report_bytes` `tests/conftest.py:1009`. **`MAX_ADDENDUM_HITS_PER_REGION` and the encoder name: `NEW — created in Phase 3`.** |
| 12 | C-31: every universal claim's input set derived from code | ✓ | D2 crash sites (grep → exactly 2, §4.1) · `_line_bytes` consumers (grep → 5 sites / 2 modules, §6.1) · report writers (grep → 6, cross-checked for accounting, §6.5) · D1 in-domain corpus (grep → 5 test files, §6.3) · D3 observer set (grep → 7 test files incl. `test_flow_report_service.py`, §6.5) · `declared_regions` cardinality (enumerated, no cap, §5.5). |
| 13 | An AT quotes the CONSTANT, never its value | ✓ | AT-165/166 name `MAX_ADDENDUM_HITS_PER_REGION`. The only literals any AT carries are **3571 / 3572**, which are properties of the CPython interpreter limit, not of a constant this batch defines — and both were re-derived (§6.2). |
| 14 | Every symbol/artifact claim carries `file:line` or is flagged | ✓ | §3.1, §4.1, §5.1, §5.4, §5.5 throughout; the three unresolvable names are flagged in §9. |
| 15 | Phase-1 constraint: no production source edits | ✓ | `git status --short` in the worktree shows only `.dev-flow/` additions. All patching happened in `git archive` exports at `…/Temp/claude/b63/{arch,archb}`. |
| 16 | Probe safety: bounded, temp trees deleted | ✓ | Ceilings: E ≤ 8 000 hits (§6.4), 200 addendum hits/region simulated — the 200 000-hit / 50 MB session ceiling was never approached and the fixture `01-requirements-rescoped.md` warns about was never built. `/b63/a` and `/b63/b` untouched. Exports `/b63/{arch,archb}` removed at close. |
| 17 | Frozen-engine verification done independently | ✓ | `tests/test_engine_unchanged.py:120-130` and `tests/test_tui_directionb.py:5443-5454` both read; `grep -c "report_service" tests/test_engine_unchanged.py` → **0**. |
| 18 | No id collision with live ids | ✓ | §2 — full `git grep` census of `R-TUI-*`, `HLR-*`, `LLR-*`, `AT-*`. `R-TUI-089..094` left RESERVED; `R-TUI-079/080/081` (the REV-4 collision) are **not** used. |

---

*Probe scripts (not part of the deliverable, retained only for the duration of Phase 1):*
`…/Temp/claude/b63/arch/p1_d3.py` · `p2_d2.py` · `p3_plugin.py` · `p4_d1.py` ·
`…/Temp/claude/b63/patch_d3.py` · `seam_probe.py`.
