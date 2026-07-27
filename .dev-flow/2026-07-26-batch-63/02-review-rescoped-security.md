# batch-63 (RE-SCOPED) — Phase-2 review: SECURITY lens

**Reviewer:** independent security lane · **Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main`
**Inputs reviewed:** `01-requirements-rescoped.md` · `00b-measurements-rescoped.md` ·
`01-requirements-rescoped-architect.md` · `01b-qa-catalog-rescoped.md`
**Constraint honoured:** review only — **zero production source edits, zero edits to Phase-1 artifacts**
(`git status --porcelain` shows only `.dev-flow/` additions). Probes read-only or `tempfile.mkdtemp`
+ `shutil.rmtree`; ceiling **E ≤ 4 000 entries / ≤ 8 000 addendum hits**, peak observed **4.1 MB**;
the declared-domain D1 fixture was **never built**. Probe scripts written to a file and invoked by
path at the short root `C:/Users/jjgh8/AppData/Local/Temp/claude/b63/r3`. `/b63/{a,b,qa,arch,archb,r1,r2}`
untouched.

---

## 1. BLUF — verdict: **BLOCKED**

Two blockers, both **introduced or left standing by the Phase-1 design**, both fixable inside the
current scope with spec-level folds — **no fold below requires new scope, new files, or new
increments.**

| # | finding | class | risk |
|---|---|---|---|
| **F1** | D1's per-region cap **re-introduces attacker-selectable truncation, and it is class-selective**: 200 attacker-supplied modification entries evict **100 %** of that region's validation-issue hits. Executed. | **blocker** | **HIGH** |
| **F2** | The report's memory-exhaustion DoS is **not closed**, and the architect's **AT-164 is unsatisfiable** — `_modifications_lines` / `_checklist_lines` are uncapped at a *measured* **988 B/entry marginal**, ×64 the addendum's per-hit cost. A correct D1 fix leaves AT-164 RED. | **blocker** | **HIGH** |
| **F3** | D2's bare-hex fallback is **forgeable as a decimal numeral** (`'9'×3572` renders as an all-decimal-digit cell understating the true length by ~10^730×) in an evidentiary document. AT-171's predicate tests less than its label. | major | MED |
| **F4** | The phrasing `00b` M-6 **explicitly retracted** ("the writer and the accounting share ONE encoder") survives as the architect's §5.2 **ruling heading**. That exact wording already caused one lane to ship an 11-byte-worse **undercount** — and in `flow_report_service` the allocator **gates emission**. | major | MED |
| **F5** | **AT-id collision across the two Phase-1 lanes**: 9 of 12 ids bind to different observables. `fail-closed` is AT-171 (architect) and AT-170 (qa). | major | MED |
| **F6** | "Fail-closed / never a partial document" — the **label is broader than the predicate**. Neither writer is atomic; a mid-write `OSError` leaves a partial file matching `REPORT_FILENAME_REGEX`. Executed. | minor | MED |
| **F7** | AT-174 silently diverges from `00b` M-7's ruling (`>=` vs `== +1`). | minor | LOW |
| **F8** | A **negative** `Length` is constructible; no AT covers the D2 helper's negative domain. | minor | LOW |
| **F9** | `write_flow_report`'s `Raises:` docstring names `write_text`. | minor | LOW |

**Explicitly cleared (no finding):** the `write_bytes` swap opens **no new input path and changes no
file permission or overwrite semantics** (§4 V1) · `flow_report_service`'s **redaction posture is
undisturbed** (§4 V2, verified by blob sha, not grep) · the lone-surrogate sibling encode-DoS is
**already closed** by `md_safe` (§4 V3) · no secret value appears anywhere in this document (§5).

---

## 2. Blockers

### F1 — the per-region cap re-introduces attacker-selectable truncation, class-selectively `[blocker · HIGH]`

**What.** `MAX_ADDENDUM_HITS_PER_REGION` (HLR-100 / LLR-100.1) is a **first-K-in-producer-order** cut.
The architect's Q-2 considered only *per-region vs document-wide* budgeting and concluded per-region
avoids attacker-selectable truncation. It does not: the selectability moved from the **region** axis
to the **hit-class** axis inside a region, where it is worse, because the producer order is fixed and
puts the least security-relevant class first.

**Where.** `s19_app/tui/services/report_service.py:1513-1537`. Inside one region the shipped producer
order is, per variant: **all** modification hits of a summary (`:1518`), then that summary's issue
hits (`:1524`), and only after every summary, the check-result issue hits (`:1532`).

**Why it matters.** Modification entries are 100 % attacker-supplied through the change file;
validation issues are the tool's own findings — the evidence an operator reads the addendum *for*.
A first-K cut therefore lets a crafted change file **push every finding for a region past the cut**
while the document reports only a generic "≥ K matches". Executed on the shipped
`_addendum_lines` (probe A, `.../b63/r3/pA.py`):

```
  mods=    5 issues=  5 cap= 200 | total_hits=   10 | first_issue_index=    5 | issues_surviving_first_200=5/5
  mods=  199 issues=  5 cap= 200 | total_hits=  204 | first_issue_index=  199 | issues_surviving_first_200=1/5
  mods=  200 issues=  5 cap= 200 | total_hits=  205 | first_issue_index=  200 | issues_surviving_first_200=0/5
  mods=  250 issues=  5 cap= 200 | total_hits=  255 | first_issue_index=  250 | issues_surviving_first_200=0/5

  summaries=3 mods_each=100 cap=200 | total=303 | issue indices=[100, 201, 302] | issues surviving=1/3
  summaries=1 mods_each=300 cap=200 | total=301 | issue indices=[300] | issues surviving=0/1
```

**Attack path.** Operator loads a change file (accepted by the shipped parser) carrying ≥ K in-region
`applied` entries → generates a project report over a project with declared regions → the addendum
for that region lists K benign modifications and **zero** validation issues, under a notice that says
only "at least K matches". The suppressed class is exactly `CHG-COLLISION` / `CHG-ADDRESS-SYNTAX` /
check-run findings. Check-result issues (`:1532`) are the *last* producer and are therefore the
**first** class to disappear, at any K.

**Recommendation (fold into LLR-100.1, no new scope).** Make the cap **per hit-class**, not per
region — three independently bounded, independently traversal-bounded lists (`K` modifications,
`K` summary issues, `K` check issues), concatenated in the shipped order. Cost stays
`O(R × 3K)`; the byte-identity arm (LLR-100.4 / AT-167) is unaffected because the in-domain
maximum is **2**. Then extend the AT that makes it observable:

> **AT-166 (architect) / AT-165 (qa) additional clause:** with a fixture whose in-region
> modification hits exceed the cap **and** which carries at least one summary issue and one
> check issue, the rendered region contains **at least one hit of every class that produced one**.
> RED counterfactual: a single shared per-region list — executed above, `0/5` issues survive.

If per-class is rejected, the **minimum** acceptable fold is that the truncation notice names the
classes it stopped scanning, so the document does not present a class-suppressed listing as a
complete one.

---

### F2 — the memory DoS is not closed, and AT-164 cannot pass `[blocker · HIGH]`

**What.** Two claims in the Phase-1 set are not supported by the code:

1. The scope ruling frames D1 as "the memory-exhaustion DoS … the most likely cause of the host RAM
   exhaustion". The addendum is **not** the dominant term at ordinary R and V.
2. The architect's **AT-164** observable is *"Peak resident memory of `generate_project_report` does
   not grow when the per-variant entry count is multiplied"*. `_modifications_lines` and
   `_checklist_lines` are **uncapped in E** and are called unconditionally, so **AT-164 is RED after
   a perfectly correct D1 fix.** A gate that cannot pass is the same defect class as one that cannot
   fail: the predictable Phase-3 response is to quietly weaken it.

**Where.**
- `report_service.py:963` — `entries = [entry for summary in result.change_summaries for entry in summary.entries]`, no cap, one table row appended per entry (`:994-1000`).
- `report_service.py:1095` `_checklist_lines` — same shape, row at `:1171`.
- Executed source census (probe B3): cap tokens (`MAX_*`, slice, `break`) inside each body →
  `_modifications_lines: NONE` · `_checklist_lines: NONE` · `_addendum_lines: NONE`.

**Executed evidence** (probe B / F, **R = 0 — the addendum is never called**):

```
      E    peak_bytes   file_bytes   B/entry
    250       411709        29599    1646.8
    500       651815        56599    1303.6   x1.58 vs prev E
   1000      1146663       110603    1146.7   x1.76 vs prev E
   2000      2134607       218603    1067.3   x1.86 vs prev E

   marginal B/entry  1000->2000: 959.3
   marginal B/entry  2000->4000: 988.0
```

The peak tracks E with the addendum entirely absent, and the **marginal** cost is **988 B/entry** —
about **11×** the addendum's measured 89 B/hit. Extrapolating from the marginal constant against the
shipped upstream ceiling (`s19_app/tui/changes/io.py:226`, `MF_ENTRY_COUNT_CEILING = 100_000`, which
bounds **one** change document; `change_summaries` per variant and variants per project are both
unbounded lists):

```
   ONE change document at the ceiling            : ~99 MB peak
   8 documents x 8 variants at the ceiling       : ~6.3 GB   -- UNAFFECTED by D1's addendum cap
```

**And the addendum itself stays a DoS after the fix.** §5.5 correctly records that
`options.declared_regions` has no cardinality cap (only `DECLARED_REGION_NAME_MAX = 80` on the
*name*). Post-fix the addendum costs `R × K × ~89 B` ≈ **17.8 kB per declared region** with `R`
manifest-fed and bounded only by `READ_SIZE_CAP_BYTES` (`io.py:222`, 256 MB). R-1 is filed "high,
accepted" — that is the right call for *scope*, but the BLUF's "**bounds what it materialises AND
what it traverses**" plus AT-164's "does not grow" together read as closure, and they are the
batch's own document asserting what it does not honour.

**Attack path.** A project carrying several change documents at the entry ceiling across several
variants exhausts host memory during report generation regardless of D1. Alternatively, a manifest
declaring ~56 000 regions costs ~1 GB in the addendum alone *after* the fix.

**Recommendation (folds, all spec-level).**
1. **Re-key AT-164 to `_addendum_lines`, not to `generate_project_report`.** The qa lane already
   does this (its AT-166 keys on `_addendum_lines` under `tracemalloc`) — adopt that surface and
   drop the whole-report wording. Keep the shipped-surface observation as AT-165's *count* assertion
   (`TC-453`), which is satisfiable.
2. **Extend OB-1.** The PR must state, next to "batch-63 does not close M-2", that it **does not
   close the report's memory-exhaustion axis either**: `_modifications_lines` / `_checklist_lines`
   remain uncapped at a measured 988 B/entry, and the addendum remains linear in an unbounded R at
   ~17.8 kB/region. Both numbers, with their inputs, in the PR body.
3. **Carry to `.dev-flow/BACKLOG.md`** as a named axis: *"`_modifications_lines` / `_checklist_lines`
   uncapped in E — 988 B/entry marginal, 6.3 GB at 8 documents × 8 variants at
   `MF_ENTRY_COUNT_CEILING`"*. This is a peer of the twelve document axes, not a subset of them:
   it is a **resident-memory** axis, which no document byte-bound reaches.

---

## 3. Major and minor findings

### F3 — the D2 fallback can forge a decimal value `[major · MED]`

**What.** LLR-101.1 specifies only *"a hexadecimal form otherwise"*, and the qa lane's AT-171
constrains the fallback cell to be **non-empty** and **distinguishable from `_format_bytes(None)`'s
`-`**. Neither requires it to be distinguishable from **a decimal value** — which is what the column
means. The attacker picks the address pair, therefore the hex digits.

**Where.** `report_service.py:996` and `:1171` (the `Length` cell), under the chosen fix shape (d).

**Executed** (probe G):

```
   value = int('9'*3572, 16)  ->  decimal RAISES, fallback f'{v:X}' = '9'*3572
   fallback cell is all-decimal-digits: True   len=3572
   the cell UNDERSTATES the byte length by ~10^730x while looking legitimate
```

A crafted entry renders a `Length` cell that is a **syntactically valid decimal numeral**, silently
understating the true byte length by ~10^730×, inside the document the batch itself calls
*evidentiary*. Probe D2b confirms the leading character is attacker-selectable (`lead=9` →
`90000…`, first char a digit).

**Why it matters.** D2 converts a crash into a rendered value. A crash is honest; a wrong-but-plausible
number is not. This is the same failure the batch was founded to fight, arriving through the fix.

**Recommendation.** Amend **LLR-101.1** to: *the helper shall return the decimal form when the
interpreter can produce it, and otherwise a form that is **not parseable as a decimal numeral** —
`0x`-prefixed hexadecimal.* Amend **AT-171**'s observable to assert the fallback cell **starts with
`0x`** (and therefore `not cell.isdigit()`), with the RED counterfactual being the bare-hex
rendering above. Cost: one prefix, one assertion. `REPORT_CELL_CHARS` not being applied to `Length`
stays batch-64's axis (R-2) — this fold does not touch it.

### F4 — the retracted encoder wording survives as a normative-looking heading `[major · MED]`

**What.** `00b` M-6 retracted "the writer and the accounting share ONE encoder" and issued a
terminology ruling: *"The requirement text must say 'one encoder for the WRITERS; `_line_bytes`
unchanged', never 'shared by the writer and the accounting'."* The architect artifact reproduces the
banned phrase verbatim as the **title and bolded ruling sentence of §5.2** ("RULING D3-A — the writer
and the accounting share ONE encoder"). Its *normative* text (LLR-102.2, `_line_bytes >= len(encoder)`)
is correct, and §5.2 is labelled informative — but the heading is what an implementer skims.

**Where.** `01-requirements-rescoped-architect.md` §5.2 heading and its bolded "Ruling:" sentence, vs
`00b-measurements-rescoped.md` M-6.

**Why it matters (security, not style).** This exact ambiguity already produced a measured wrong
implementation: the qa lane implemented `_line_bytes := len(encoder(lines))` and measured
`budget.used` **11 bytes UNDER the file, constant across fixture size** — a *worse* undercount than
the CRLF defect it replaces. And in `flow_report_service.py:310` the budget **gates emission**
(`put()` drops a whole section and records it truncated when `fits()` says no, `:308-315`), so an
undercounting allocator there decides what the document contains, not merely how large it is.

**Recommendation.** Retitle §5.2 to *"RULING D3-A — one encoder for the WRITERS; `_line_bytes`
unchanged"* and replace the bolded ruling sentence with the same words. One-line fold; blocks a
re-derivation of a measured-wrong design.

### F5 — the two Phase-1 lanes allocate the same AT ids to different observables `[major · MED]`

**What.** The architect and qa catalogs both allocate `AT-164 … AT-175` and disagree on **9 of 12**.

| id | architect | qa |
|---|---|---|
| AT-164 | whole-report peak memory flat in E | per-region hit bound |
| AT-165 | hit count ≤ cap | honest `≥K`, never a total |
| AT-166 | notice names the constant, no total | tracemalloc cost law |
| AT-169 | `W−1` decimal identity | checklist twin |
| AT-170 | checklist twin | **fail-closed / no partial document** |
| AT-171 | **fail-closed / no partial document** | honest fallback cell |
| AT-173 | seam, flow writer | `len(report_bytes) == _line_bytes − 1` |
| AT-174 | `_line_bytes >= len(encoder)` | batch-composability |
| AT-175 | no `\r` (Windows) | on-disk size **and** no `\r` |

Only AT-167, AT-168 and (loosely) AT-172 agree. The union carries ~17 distinct observables in 12 ids.

**Why it matters.** Under this project's dual traceability an `AT-NNN` is the *behavioural* contract;
any Phase-3/4 artifact citing "AT-170" is ambiguous, and the arithmetic guarantees that at least
5 observables get dropped when one list is implemented. The **security-relevant casualty** is
concrete: the fail-closed guard and the honest-cell guard occupy the same two ids from opposite ends.

**Recommendation.** Reconcile to a single numbered list before Phase 3, keeping the **union** of
observables (expand past AT-175 as needed — `AT-176…` are free by the architect's own §2 census).
Do not resolve by picking one lane's list.

### F6 — "never a partial document" is broader than what any predicate tests `[minor · MED]`

**What.** LLR-101.4 / AT-170 (qa) / AT-171 (architect) are labelled *"fail-closed is preserved: never
a partial document"* but the predicate is *"when **composition** raises, `reports/` contains no
report file"*. Write-time failure is outside it, and **neither writer is atomic**.

**Executed** (probe C2):

```
  text mode   : after mid-write OSError -> file exists=True size=50000 (pre-existing content survived: False)
  binary mode : after mid-write OSError -> file exists=True size=50000 (pre-existing content survived: False)
```

`write_bytes` is **no worse** than `write_text` here — the swap is neutral, which answers the
question this review was asked. But a mid-write `OSError` (disk full, quota, network path) leaves a
truncated report whose name still matches `REPORT_FILENAME_REGEX`
(`report_service.py:149`), so `list_project_reports` and the shipped viewer present it as a
legitimate report. Nothing in the name or the body records completeness.

**Recommendation (choose one, both cheap).**
(a) **Narrow the label** to *"a composition failure leaves no file"* so the predicate matches the
claim — this is the in-scope fold; **or**
(b) carry *"write the report to a sibling temp name and `os.replace` it into place"* to
`.dev-flow/BACKLOG.md` as a hardening item (atomic on Windows for a same-volume replace).
Not both required. Option (a) is mandatory; (b) is recommended.

### F7 — AT-174 diverges from the authoritative transcript without recording it `[minor · LOW]`

`00b` M-7 **ruled** the D3 invariant be re-keyed to `_line_bytes(lines) == len(report_bytes(lines)) + 1`
for `N ≥ 1`, on the stated ground that `>=` is a weaker pin (changing `+1` to `+2` stays green) and
`_line_bytes` has **zero** test references today (C-26 census). The architect's AT-174 adopts `>=`.
`>=` is the **security-sufficient direction** — it forbids exactly the undercount that breaks the
emission gate — so this is not a blocker. But the artifact names `00b` "authoritative" and departs
from an explicit ruling in it without a divergence note. The qa lane's AT-173 carries the `== −1`
form, so the union already contains both; F5's reconciliation should keep **both** (the `==` as the
pin, the `>=` as the safety property) and record why.

### F8 — the D2 helper's negative domain is unspecified and untested `[minor · LOW]`

`ChangeSummaryEntry(address_start=0x2000, address_end=0x1000)` constructs **without error** (probe D3)
and renders `Length` as `-4096`. No LLR or TC constrains the guarded helper's behaviour on a negative
value, and a `0x`-prefixed fallback (F3) must decide between `-0x…` and `0x-…`. Add one boundary case
to the D2 TC block (`TC-455`/`TC-466` neighbourhood): a negative length renders unchanged in-domain,
and a negative length past the digit limit renders with a leading sign.

### F9 — a docstring will go stale with the fix `[minor · LOW]`

`flow_report_service.write_flow_report`'s `Raises:` section names *"Propagated from
`mkdir`/`write_text`"*. Under LLR-102.1 that writer becomes `write_bytes`. One-line update in the
same increment; noted so it is not a review-comment surprise.

---

## 4. Cleared — the questions this review was asked, answered by execution

**V1 — no new input path; `write_bytes` is semantically neutral.** The batch adds a module constant,
a pure encoder and a pure guard; it opens no file, no socket, no subprocess. Executed comparison
(probe C1):

```
  write_text : size= 10 mode=-rw-rw-rw- oct=0o666
  write_bytes: size=  8 mode=-rw-rw-rw- oct=0o666
  modes equal: True
  after re-write over longer content: text_size=5 bytes_size=5 (both truncate)
  write_text onto a directory: PermissionError
  write_bytes onto a directory: PermissionError
```

Identical permission bits, identical truncate-on-open, identical directory-target error. The only
observable difference is the intended one: `b'l1\r\nl2\r\nl3'` → `b'l1\nl2\nl3'`. Target paths remain
timestamp-derived and non-colliding (`_report_filename`, `report_service.py:451`), so no report is
ever overwritten.

**V2 — `flow_report_service`'s redaction posture is undisturbed.** Verified by blob sha, **not** by
grep (a prior review's grep false-hit on an unchanged comment appearing as diff context):

```
$ git rev-parse HEAD:s19_app/tui/services/flow_report_service.py \
                origin/main:s19_app/tui/services/flow_report_service.py
ad756ae043759fd5f9c309f15bd0e767e8d0c26b
ad756ae043759fd5f9c309f15bd0e767e8d0c26b
```

The redactor `_redact_absolute_paths` is defined at `flow_report_service.py:228` and applied at
`:352` and `:371`, both inside `compose_flow_report` — **upstream** of the writer this batch changes
(`:456`). The proposed diff is the import block (`:65-74`) plus the writer line. Emission decisions
are provably unchanged: `_line_bytes` is unchanged (LLR-102.2), `_ByteBudget` is unchanged, therefore
every `fits()` outcome at `:310` is bit-identical pre/post fix — **no section is newly dropped and
none newly emitted**, so no message that was suppressed becomes visible.
*(Note for the orchestrator: the flow report **does** redact absolute paths — batch-60 final-gate F2.
The withdrawn D-11 control was the project-report redactor; `report_service.py:1048` records that
issue messages there are deliberately **not** path-redacted. That posture is likewise untouched:
no finding of this batch adds an emission site in `report_service`.)*

> **Obligation for Phase 3 (OB-SEC-1):** paste `git diff --numstat -- s19_app/tui/services/flow_report_service.py`
> in the review packet. Anything other than the import line and the writer line is out of the
> sanctioned diff and must be justified before merge.

**V3 — the lone-surrogate sibling DoS is already closed.** A JSON change file can carry a lone
surrogate (`json.loads` accepts `\ud800`), and `str.encode("utf-8")` raises on it — a D2-class
availability defect of a different shape. Executed (probe E): `md_safe` replaces it with `U+FFFD`
before any encode, so `_line_bytes` and the encoder both survive. Raw (un-`md_safe`'d) values still
raise, but they raise inside `_line_bytes` during **composition**, i.e. before the writer — fail-closed
is preserved either way, and the D3 encoder does not move that raise. **No finding**; recorded so the
axis is not re-opened.

**V4 — bounded-probe discipline held.** Max peak observed across all probes: **4.11 MB** (E = 4 000).
Max addendum hits materialised: **303**. Every temp tree created with `tempfile.mkdtemp` and removed
in a `finally`. The declared-domain D1 fixture was never constructed; every DoS claim in this review
is a **bounded grid plus an extrapolation from a measured marginal constant**, with the constant and
its inputs printed.

---

## 5. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Each finding has what · where · why · recommendation | ✓ | §2 F1-F2, §3 F3-F9 — every entry carries all four |
| 2 | Each finding has a severity rating | ✓ | §1 table: blocker/major/minor × HIGH/MED/LOW |
| 3 | **No secret value appears in this output** | ✓ | no `.env`, key, token or credential is read or quoted; the only file contents cited are `s19_app/` source lines and synthetic in-memory fixtures |
| 4 | Verdict is explicit | ✓ | §1 — **BLOCKED**, with the two blockers named and their folds stated |
| 5 | New tool/integration scope + blast radius addressed | ✓ | §4 V1 — no new external surface; the change is one constant, one pure encoder, one pure guard. Blast radius of the writer swap measured: identical mode bits / truncation / error behaviour |
| 6 | Attacker-selectable truncation question answered | ✓ | **F1 — yes, and worse than the superseded design**: executed `0/5` issue survival at `mods=200, cap=200` (probe A) |
| 7 | Fail-closed preservation verified **by execution**, incl. abort mid-write | ✓ | **F6** + §4 V1 — probe C2 (mid-write `OSError` in both modes), probe C1 (writer equivalence). `write_bytes` is neutral; the AT **label** overclaims |
| 8 | D2 leak / fabrication question answered | ✓ | **F3 — the fallback can forge a decimal numeral**: `'9'×3572`, `isdigit() == True`, understating ~10^730× (probe G); leading char attacker-selectable (probe D2b) |
| 9 | New input path / permission / overwrite semantics | ✓ | §4 V1 — none; `0o666` both, truncate-on-open both, `PermissionError` on a directory both |
| 10 | `flow_report_service` redaction posture verified by blob sha, not grep | ✓ | §4 V2 — `HEAD` == `origin/main` == `ad756ae0…`; redactor at `:228`, applied `:352`/`:371`, upstream of the changed writer; `fits()` decisions provably unchanged |
| 11 | `assumed` claims with a security consequence flagged | ✓ | flagged **by the lanes**: G-7 (`<1.5` ratio not derived against a fixed impl), R-1 (R unbounded), R-2 (unbounded `Length` cell), G-5 (traversal vs output). **Unflagged and found here:** F2 (uncapped `_modifications_lines`/`_checklist_lines`), F1 (intra-region class ordering), F3 (fallback confusability) |
| 12 | Probe safety: bounded, temp trees deleted, no forbidden fixture built | ✓ | §4 V4 — peak 4.11 MB, ≤ 303 addendum hits, `mkdtemp`+`rmtree`, declared-domain fixture never built, short root `/b63/r3`, `/b63/{a,b,qa,arch,archb,r1,r2}` untouched |
| 13 | No production source edited, no Phase-1 artifact edited | ✓ | `git status --porcelain` → only `.dev-flow/` paths; all probes read-only imports of the shipped tree |

---

## 6. Verdict

- [ ] OK to ship
- [ ] OK to ship with the listed mitigations applied first
- [x] **Block** — F1 and F2 must be folded into the Phase-1 artifacts before Phase 3 opens.

**Release condition.** Every fold is spec-level and inside the current scope:

1. **F1** — LLR-100.1 becomes a **per-hit-class** cap; add the "every producing class is represented"
   clause to the notice AT.
2. **F2** — re-key **AT-164** to `_addendum_lines`; extend **OB-1** so the PR states the report's
   resident-memory axis is **not** closed (988 B/entry marginal · 6.3 GB at 8 documents × 8 variants
   at `MF_ENTRY_COUNT_CEILING` · 17.8 kB per declared region post-fix, R unbounded); carry the axis
   to `.dev-flow/BACKLOG.md`.
3. **F3** — LLR-101.1 mandates a **`0x`-prefixed** fallback; AT-171 asserts the prefix.
4. **F4** — retitle architect §5.2 per `00b` M-6.
5. **F5** — reconcile the AT registry to one list carrying the **union** of both lanes' observables.
6. **F6** — narrow the fail-closed label to composition failure (and optionally carry the atomic
   write to BACKLOG).
7. **OB-SEC-1** — Phase 3 pastes `git diff --numstat` for `flow_report_service.py`.

F7 / F8 / F9 are recommendations and do not gate.
