# batch-63 (RE-SCOPED) — Phase-2 RE-GATE: SECURITY lens

**Reviewer:** independent security lane (same lane that filed `02-review-rescoped-security.md`)
**Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main`
**Under audit:** `01-requirements-rescoped-consolidated.md` **revision 3** (normative fold)
**Audited against:** my own F1..F9 as written, **not** the fold's amendment table.
**Constraint honoured:** audit only — `git status --porcelain` shows `M .dev-flow/state.json` +
`?? .dev-flow/2026-07-26-batch-63/` and nothing else; `git diff --numstat origin/main -- s19_app/`
is **empty**. Counterfactuals ran in a `git archive HEAD s19_app` export at the short root
`C:/Users/jjgh8/AppData/Local/Temp/claude/b63/g2`; `/b63/{a,b,g1,qa,r3}` untouched. Bounded probes:
max V=3, max 400 entries/class, K=200, R=50; **peak observed 0.32 MB**; the declared-domain D1
fixture was **never built**; every temp tree removed in a `finally`.

---

## 1. BLUF — verdict: **OK-with-folds, CONDITIONAL on an operator-signed risk acceptance for F2**

Absent that signature the verdict is **BLOCKED**. This is not a formality: F2 is a HIGH availability
finding that the fold discharges **by disclosure**, and disclosure is risk acceptance, not closure.
An orchestrator cannot accept a HIGH on the operator's behalf.

| prior finding | fold's answer | status | new severity |
|---|---|---|---|
| **F1** — attacker-selectable, class-selective truncation | A-07 per-hit-class cap + `AT-165` | **PARTIALLY CLOSED** | **MED** (was HIGH) |
| **F2** — the memory DoS is not closed | A-05/A-06 re-scope + withdraw `AT-164` + extend OB-1 | **ACCEPTED RISK — not closed** | **HIGH, unmitigated** |
| **F3** — forgeable `Length` cell | `0x` prefix (`LLR-101.2`, `AT-171`) | **PARTIALLY CLOSED** — positive domain closed, negative domain re-opens it | **MED** |
| **F4** — retracted encoder phrasing | A-03 | **CLOSED** ✓ | — |
| **F5** — AT-id collision | A-01 single registry | **CLOSED for ids; observables were lost** → see N-1 | — |
| **F6** — fail-closed label > predicate | A-14 narrow to `AT-170` | **NOT CLOSED** — the narrowed label is still unachievable | LOW-MED |
| **F7** — `AT-174` vs `00b` M-7 | `AT-174` is now a `+1`/partition-invariance pin | **CLOSED** ✓ | — |
| **F8** — negative `Length` domain | *(not addressed)* | **RE-OPENED and promoted** — it is now F3's live vector | **MED** (was LOW) |
| **F9** — stale `Raises:` docstring | *(not addressed)* | open | LOW |

**Newly opened by the fold**

| # | finding | severity |
|---|---|---|
| **N-1** | No AT binds the **second** `LLR-101.1` site (`_checklist_lines:1171`). Both source lanes carried a "checklist twin" AT; the consolidation dropped it. Measured: a change-only fixture never reaches `:1171`, so `AT-168/169/171` all pass with half the "exact two-member set" unguarded. | **MED** |
| **N-2** | No black-box AT asserts the cap is *enforced* (rendered hits ≤ K per class). Both lanes had one; the fold has only the white-box `TC-441`. | LOW |
| **N-3** | `document_bytes(text: str) -> bytes` — **cleared.** No new input path, no new import edge, no cycle, identical permission/truncation/error semantics, no report is ever read back. §5. | *(cleared)* |

**Correction to my own prior review, stated loudly.** My F1 called class 3 (`:1532`) "the tool's own
findings". The code says otherwise: `CheckRunResult.issues = list(document.issues)`
(`s19_app/tui/changes/check.py:399`) and `ChangeSummary.issues = list(document.issues)`
(`changes/apply.py:363`). **All three addendum classes are change/check-document-derived**, so the
attacker controls the *cardinality* of every class. The CHECK_FAIL entries — the tool's real
memory-mismatch verdicts — never enter the addendum at all. This strengthens F1's residual and
weakens the fold's implicit premise that a per-class cap restores a non-attacker class.

---

## 2. F1 — per-hit-class cap: the cross-class attack is closed, the intra-class one is not

**Status: PARTIALLY CLOSED. `AT-165` is GREEN under every attack below.**

### 2.1 What A-07 genuinely fixes

Executed against the shipped producer order (`report_service.py:1518` mods → `:1524` summary issues
→ `:1532` check issues), with the fold's `LLR-100.1` implemented faithfully (three independently
bounded, independently traversal-bounded classes, concatenated in shipped order), probe
`.../b63/g2/p1_f1.py`:

```
A4 - attacker controls TWO of three classes at once
   mods=400 syntax=400 K=200 | class1=200 class2=200 class3=3
   class-3 (check-file issues) FULLY protected by the per-class cap: True
```

Revision 2's single per-region list gave `0 of 5` at `mods=200,cap=200`. The per-class cap gives
`3 of 3`. **Cross-class eviction is genuinely closed** — that is a real fix and I am not walking it
back.

### 2.2 What it does not fix — intra-class eviction

The cap is still a **first-K-in-document-order** cut *inside* each class, and the attacker supplies
the document that fixes the order.

```
A2 - flood ONE class (class-2) with attacker-triggered CHG-ADDRESS-SYNTAX;
     the CHG-COLLISION is last in document order
   syntax_issues= 199 K=200 | CHG-COLLISION survives=1/1 | AT-165 = True
   syntax_issues= 200 K=200 | CHG-COLLISION survives=0/1 | AT-165 = True
   syntax_issues= 400 K=200 | CHG-COLLISION survives=0/1 | AT-165 = True
```

`CHG-COLLISION` (ERROR severity — "one change silently overwrites another", `changes/validate.py:16`)
is evicted by 200 `CHG-ADDRESS-SYNTAX` warnings the same attacker authored. **`AT-165` is GREEN
throughout**, because a class-2 row survives — it is just the wrong one.

### 2.3 What it does not fix — cross-variant eviction

The class budget is shared across **all** variants and **all** summaries in a region. One flooded
change file suppresses every other variant's findings of that class:

```
A3 - v1's change file floods class 2; v2 and v3 carry the collision the operator needs
   K=200 | CHG-COLLISION by variant: {'v1': 0, 'v2': 0, 'v3': 0}   (expected 0/1/1)
   AT-165 'every producing class represented' = True
```

**2 of 2 legitimate collisions gone; the gate is green.**

### 2.4 `AT-165`'s predicate is weaker than its label — the orchestrator's hypothesis, confirmed

- **Label:** "every producing hit-class is represented in a capped region's addendum".
- **What that is offered as:** the discharge of a finding about *evidence being suppressed*.
- **What it tests:** that the three-way concatenation is non-empty per class — a property of the
  **implementation shape**, not of the evidence. It cannot distinguish "the operator's collision
  survived" from "200 of the attacker's own syntax warnings survived and the collision did not".

This is precisely the batch's own proven rule — *a predicate must test what its LABEL claims*
(MEMORY `project_batch_63_report_bounds.md`). `AT-165` is a vacuous check with respect to the
finding it discharges.

### 2.5 Recommendation — three folds, all spec-level, none new scope

1. **Narrow `AT-165`'s label to what it tests:** *"no producing class is wholly evicted by another
   class"*. RED counterfactual stays revision 2's shared list (`0/5`, executed). Do **not** let it
   stand as the F1 discharge.
2. **Strengthen `LLR-100.3` (the residual's actual control).** The notice must name **which classes
   were cut** and that later variants may be unrepresented — e.g. *"at least 200 modifications and
   at least 200 change-file issues in this region; scanning stopped, later variants not
   represented."* Today `LLR-100.3` requires only `at least K` with no total. This was the
   *minimum* fold my prior F1 offered and it is not in the document. Extend `AT-167` to assert the
   class names appear.
3. **Record the residual explicitly** in `HLR-100`'s "what this deliberately does NOT claim"
   paragraph: *within a class, and across variants, first-K in attacker-controlled document order
   still decides what is shown.*

With folds 1-3 the residual is **MED and disclosed**, and I do not block on it.

---

## 3. F2 — this is risk acceptance, and it needs the operator's name

**Status: ACCEPTED RISK, not closed. HIGH, unmitigated.**

**Answering the question asked directly: stating the limitation is _not_ a discharge.** A finding is
discharged when the risk is removed, reduced, or transferred. A-05/A-06 do none of those — they
remove the *claim*, which is honest and necessary, and leave the *risk* exactly where it was:

- `report_service.py:963` `_modifications_lines` and `:1095` `_checklist_lines` remain uncapped at a
  measured **988 B/entry marginal**, ~11× the addendum's 89 B/hit.
- Extrapolated from that measured constant against `MF_ENTRY_COUNT_CEILING = 100_000`
  (`tui/changes/io.py:226`): ~99 MB for one change document at the ceiling; **~6.3 GB** at
  8 documents × 8 variants — untouched by anything in batch-63.
- Post-fix the addendum itself is still **linear in an unbounded R**: measured `R=50, K=200` →
  6 415 B/region (probe A5), against `options.declared_regions` with no cardinality cap.

**What the fold got right.** Withdrawing `AT-164` and re-keying the cost observable to `AT-166`
(*"the addendum's own resident cost stops tracking V×E"*) is exactly my F2 recommendation #1, and
`AT-166` **is** satisfiable — with a per-class cap the function's own allocation is ≤ 3K rows
regardless of V and E. Good. That closes the "gate that cannot pass" half of F2.

**What is missing — my F2 recommendations #2 and #3, both cheap.**

| my rec | fold | gap |
|---|---|---|
| #1 re-key `AT-164` → `_addendum_lines` | A-06 withdraw + `AT-166` | ✓ done |
| #2 extend OB-1 so the PR states the resident axis is not closed, **with both numbers and their inputs** | OB-1 states the axis; **no numbers** | partial |
| #3 carry the axis to `.dev-flow/BACKLOG.md` as a **resident-memory** axis | **absent** — OB-2 carries the id registry, OB-3 carries `diff_report_service`; nothing carries this | **not done** |

§3.2 asserts the two functions "are batch-64's subject". Nothing makes that true. The nearest
`BACKLOG.md` line (line 25, from batch-62 sec F4) frames the same functions as a **document-byte**
problem (*"~208 MB, ~99× the declared 2 MiB `REPORT_MAX_TOTAL_BYTES`"*) and proposes *"charge them
to `_ByteBudget`"* — a remedy that bounds the **output** and does **not** bound resident memory,
because the row list is materialised before the budget ever sees it. My prior F2 said this in
terms: *"a peer of the twelve document axes, not a subset of them — a resident-memory axis, which no
document byte-bound reaches."* That distinction is still not on the queue.

### Recommendation

1. **Operator sign-off, by name, on the residual.** Wording for the PR body and the batch record:
   *"batch-63 does not close the report's resident-memory exhaustion axis. `_modifications_lines`
   and `_checklist_lines` remain uncapped at a measured 988 B/entry marginal (~6.3 GB at 8 change
   documents × 8 variants at `MF_ENTRY_COUNT_CEILING`), and the addendum remains linear in an
   unbounded declared-region count at ~6.4 kB/region at K=200. Accepted for this batch by
   <operator>."* Numbers in the body, per my F2 rec #2.
2. **Add OB-4**: carry the axis to `.dev-flow/BACKLOG.md` as its own line, explicitly framed as
   **resident memory**, and explicitly noting that line 25's `_ByteBudget` remedy does not close it.
3. Keep OB-1's `> TRUNCATED … (report size cap: N bytes)` note — that marker still asserts a bound
   the document violates, and the fold is right to say so.

Fold 1 is the gate condition. Folds 2-3 are one line each.

---

## 4. F3 / F8 — the `0x` prefix closes the positive domain and opens the negative one

**Status: PARTIALLY CLOSED. `AT-171` as written forces a malformed cell, or goes RED on a correct
implementation.**

Positive domain, closed (probe `.../b63/g2/p2_f3_f6.py`, `sys.get_int_max_str_digits() = 4300`):

```
B1  positive: cell[:6]='0x9999' len=4303 startswith0x=True isdigit=False -> AT-171 GREEN
```

The `'9'×W` forgery from my F3 no longer renders as a decimal numeral. Fold A-11 works.

**The forge that survives.** `ChangeSummaryEntry(address_start > address_end)` constructs without
error (my prior probe D3) and both sites render the raw expression
`entry.address_end - entry.address_start` (`report_service.py:996`, `:1171`) with **no sign guard**.
`LLR-101.2` and `AT-171` are silent on sign placement:

```
B2  f'0x{v:X}' with v<0  -> '0x-99999'...  startswith0x=True   AT-171 GREEN=True
    is it a VALID hex literal? NO -> ValueError. The AT-171-COMPLIANT cell is UNPARSEABLE.
    well-formed alternative '-0x999999'... startswith0x=False -> AT-171 goes RED on the CORRECT fix.
```

So `AT-171`'s predicate — *"the guarded cell starts with `0x`"* — **rewards the malformed rendering
and punishes the correct one**. In an evidentiary document whose purpose is correlating symbols to
addresses, `0x-9999…` is a cell no consumer can parse and no reviewer can sanity-check. This is my
F8 (filed LOW, unaddressed by the fold) promoted to the live vector for F3.

Secondary, recorded not blocking: the guarded cell is **4 303 characters** and `REPORT_CELL_CHARS`
(512) is not applied to `Length` (probe B3). That stays batch-64's R-2 axis; the `0x` mandate adds
2 characters to it and does not change its shape.

### Recommendation (two lines)

- **`LLR-101.2`** → *"the alternative form **shall** match `^-?0x[0-9A-F]+$` — sign first, then the
  `0x` prefix — so it is a well-formed hexadecimal literal, can never be read as a decimal numeral,
  and is not confusable with `_format_bytes(None)`'s `-`."*
- **`AT-171`** → assert `re.fullmatch(r'-?0x[0-9A-F]+', cell)` and `cell != '-'`. RED
  counterfactuals: bare `'9'×W` (fails the pattern) **and** `0x-…` (fails the pattern). Add the
  negative-width case to the D2 TC block.

---

## 5. F6 — the narrowed label is still not achievable

**Status: NOT CLOSED.**

The fold's `AT-170` reads *"no report file is left behind when **generation aborts** (fail-closed)"*
(§2 registry) / *"On abort, no file matching `REPORT_FILENAME_REGEX` remains"* (§4.4). "Generation"
and "abort" both include the write. And `LLR-101.4` states the rationale as fact: *"Generation shall
continue to write the report in a single terminal write, **so an abort leaves no file**."*

That clause is false. `write_text` / `write_bytes` are a single *API* call, not a single *OS* write;
the payload is flushed in chunks. Probe `.../b63/g2/p3_f6.py`:

```
  text   writer: mid-write OSError -> file exists=True size=100000 of 200000 | matches REPORT_FILENAME_REGEX=True
  bytes  writer: mid-write OSError -> file exists=True size=100000 of 200000 | matches REPORT_FILENAME_REGEX=True
```

A truncated report whose name still matches `REPORT_FILENAME_REGEX` (`report_service.py:149`) is
presented by `list_project_reports` and the shipped viewer as a legitimate report. The `write_bytes`
swap is **neutral** here — that part of my V1 clearance stands — but the fold moved the label without
making it true.

**Recommendation (one word each, both mandatory).**
- `AT-170` → *"when **composition** raises, no file matching `REPORT_FILENAME_REGEX` remains"*.
- `LLR-101.4` → delete the *"so an abort leaves no file"* clause, or qualify it *"…so a
  **composition** failure leaves no file; a write-time failure can still leave a partial file —
  see BACKLOG"*.
- Optional, recommended, not gating: carry *"write to a sibling temp name and `os.replace` into
  place"* to `.dev-flow/BACKLOG.md` (atomic on Windows for a same-volume replace).

---

## 6. N-1 — the fold lost the second `LLR-101.1` site's AT `[MED]`

`LLR-101.1` names *"the exact two-member set derived by AST census"*: `report_service.py:996`
(`_modifications_lines`) and `:1171` (`_checklist_lines`). **No AT in the fold binds both.** Both
source lanes had one — architect `AT-170` "checklist twin", qa `AT-169` "checklist twin" — and the
consolidation from ~17 observables into 11 ids dropped it. My F5 explicitly recommended keeping the
**union** and expanding past `AT-175`; the fold consolidated instead.

Why it bites: the two sites take **disjoint inputs**. `_modifications_lines` iterates
`result.change_summaries[].entries`; `_checklist_lines` iterates `result.check_results[].entries`.
A D2 fixture built from change data alone never reaches `:1171` — executed:

```
C1  _checklist_lines rows with check_results=[] :
    ['### Checklists', '', 'No checklists were executed for this variant.', '']
```

So `AT-168` ("a report exists at width W"), `AT-169` (byte identity at W−1) and `AT-171` (the guarded
cell) can **all** pass with `:1171` unguarded — and the denial `HLR-101` exists to remove persists
for every project that runs a check. **Fix:** restore the twin as `AT-176` (`AT-176+` are free by the
fold's own §2 census), or make `AT-168`'s fixture normatively require a variant carrying **both** a
change summary and a check result, with the assertion applied to both tables.

**N-2 `[LOW]`** — no black-box AT asserts *rendered hits ≤ K per class*. Architect `AT-165` and qa
`AT-164` both carried it; the fold has only `TC-441` (white-box consumption counter). `AT-166`
(resident flatness) covers it indirectly. Recommend folding the count assertion into `AT-166`'s
observable rather than minting an id.

---

## 7. N-3 — `document_bytes`: cleared, by sha and by measurement

Verified **without grep**, per the standing instruction.

**Blob shas — both files are byte-identical to `origin/main`, and no production source is touched:**

```
$ git rev-parse HEAD:.../flow_report_service.py origin/main:.../flow_report_service.py \
                HEAD:.../report_service.py      origin/main:.../report_service.py
ad756ae043759fd5f9c309f15bd0e767e8d0c26b
ad756ae043759fd5f9c309f15bd0e767e8d0c26b
385b92aeade0e5d57ad54454ed07adae35d80fd6
385b92aeade0e5d57ad54454ed07adae35d80fd6

$ git diff --numstat origin/main -- s19_app/      ->  (empty)
```

**No new input path.** `document_bytes(text: str) -> bytes` is a pure `str → bytes` function. It
opens no file, no socket, no subprocess. Its `str` typing is what keeps `compose_flow_report`'s
public `-> str` (`flow_report_service.py:273`) unchanged.

**No new import edge, no cycle.** `flow_report_service.py:69-74` **already** imports
`REPORT_MAX_TOTAL_BYTES, REPORTS_DIR_NAME, _ByteBudget, _line_bytes, _report_filename` from
`.report_service`. `document_bytes` is a **+1 line inside an existing import tuple**.
`report_service`'s own import block (`:39-56`) does not name `flow_report_service` — the edge stays
one-directional, so `LLR-102.1` cannot introduce a circular import.

**No permission or overwrite change** (re-measured, probe C3):

```
   write_text  mode=0o666 size=14      write_bytes mode=0o666 size=12
   modes equal: True
   both truncate on rewrite: True
   write_text onto a dir: PermissionError ; write_bytes onto a dir: PermissionError
   only intended difference: b'hello\r\nw' -> b'hello\nwo'
```

Target paths stay timestamp-derived and non-colliding (`_report_filename`, `report_service.py:451`),
so no report is overwritten.

**Redaction posture untouched.** `_redact_absolute_paths` is defined at `flow_report_service.py:228`
and applied at `:352` / `:371`, both inside `compose_flow_report` — **upstream** of the writer at
`:456`. `_line_bytes` is unchanged by `LLR-102.2`, `_ByteBudget` is unchanged, therefore every
`fits()` outcome at `:310` is bit-identical pre/post, so `put()` drops and emits exactly the same
sections — **no suppressed message becomes visible**. Project-report posture likewise untouched:
`report_service.py:1048` records that issue messages there are deliberately not path-redacted, and no
finding of this batch adds an emission site.

**No report is ever read back** — neither `report_service.py` nor `flow_report_service.py` nor
`app.py` calls `read_text`/`read_bytes` on a report, so the CRLF→LF change on Windows has no
in-tree parse-back consumer.

> **OB-SEC-1 stands, unchanged.** Phase 3 pastes
> `git diff --numstat -- s19_app/tui/services/flow_report_service.py` in the review packet. Anything
> beyond the import line and the writer line is outside the sanctioned diff.

**Minor, not a finding:** `report_service` declares no `__all__`, so `document_bytes` becomes public
by naming convention only. Consistent with the module as shipped; no action.

---

## 8. Re-opened / still open from my prior review

| # | state |
|---|---|
| **F4** | **CLOSED.** The banned phrase survives in the fold only at `§5.1` line 197, *inside the quotation that records the retraction*. `HLR-102`'s normative text reads "One place bytes are made; accounting is an unchanged upper bound." Correct. |
| **F5** | **ids closed, observables lost.** One registry with per-id semantics — good, and A-01 is the right shape. But the consolidation from ~17 observables to 11 ids dropped the checklist twin (**N-1**) and the cap-count assertion (**N-2**). My F5 said keep the union and expand past `AT-175`. |
| **F7** | **CLOSED.** `AT-174` is now a pin asserting `+1`/line and partition-invariance — the `00b` M-7 form. `LLR-102.2` additionally **prohibits** the `len(join)` redefinition with the measured 182-vs-170 evidence. This is the strongest single improvement in the fold. |
| **F8** | **RE-OPENED and promoted to MED** — it is now F3's live vector (§4). |
| **F9** | **Open, LOW.** `flow_report_service.py:435` still reads *"Propagated from `mkdir`/`write_text`"* while `:456` becomes `write_bytes` under `LLR-102.1`. One-line update in increment 1. |

---

## 9. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Each finding has what · where · why · recommendation | ✓ | §2 F1, §3 F2, §4 F3/F8, §5 F6, §6 N-1/N-2 — all four elements each |
| 2 | Each finding has a severity rating | ✓ | §1 tables (MED / HIGH / MED / LOW-MED / MED / LOW) |
| 3 | **No secret value appears in this output** | ✓ | no `.env`, key, token or credential read or quoted; only `s19_app/` source lines and synthetic in-memory fixtures |
| 4 | Verdict is explicit | ✓ | §1 — **OK-with-folds, conditional on operator sign-off for F2; BLOCKED without it** |
| 5 | F1 status stated (closed / partial / accepted / open) | ✓ | §1 + §2 — **PARTIALLY CLOSED**; cross-class closed (`class3=3/3`, probe A4), intra-class and cross-variant open (`0/1`, `0/2`) |
| 6 | F2 status stated, and named as closure vs risk acceptance | ✓ | §3 — **ACCEPTED RISK, not closed**; requires the operator's name, not the orchestrator's |
| 7 | `AT-165` predicate tested against its label | ✓ | §2.4 — GREEN in all three attacks (probe A2/A3/A4) while the operator-relevant issue is evicted |
| 8 | F1 executed against the **shipped** producer order | ✓ | §2 — `:1518`/`:1524`/`:1532` read from `report_service.py:1513-1537`; probe A1 renders the real `_addendum_lines` ordering |
| 9 | F3 forge attempted against the `0x` mandate | ✓ | §4 — positive domain closed (B1); **negative domain forges through** (B2): `0x-…` passes `AT-171` and is not a valid hex literal |
| 10 | F6 narrowed claim tested for achievability | ✓ | §5 — probe B4/p3: both writers leave a 100 000 B name-conforming partial file after a mid-write `OSError` |
| 11 | New surface: no new input path / permission / overwrite change | ✓ | §7 — pure `str→bytes`; `0o666` both, truncate-on-open both, `PermissionError` on a directory both; timestamp-derived non-colliding names |
| 12 | D3 redaction posture verified **by blob sha or ± diff, never grep** | ✓ | §7 — `ad756ae0…` == `ad756ae0…`, `385b92ae…` == `385b92ae…`, `git diff --numstat origin/main -- s19_app/` empty; import direction read from `:69-74` vs `:39-56` |
| 13 | Circular-import risk of the new cross-module symbol assessed | ✓ | §7 — edge already exists one-directionally; `document_bytes` is +1 line in an existing import tuple |
| 14 | Anything the fold re-opened is named | ✓ | §8 — F8 re-opened/promoted; F5's observable loss → N-1/N-2 |
| 15 | Probe safety: bounded, temp trees deleted, forbidden fixture never built | ✓ | peak **0.32 MB** (probe A5, R=50/K=200); V≤3, ≤400 entries/class; `mkdtemp`+`rmtree` in `finally`; declared-domain D1 fixture never constructed; every DoS number is a bounded grid + extrapolation from a printed marginal constant |
| 16 | Counterfactuals ran at the short root; forbidden roots untouched | ✓ | `.../b63/g2` (`git archive HEAD s19_app`); `ls .../b63/` → `a b g1 g2 qa r3`, only `g2` written |
| 17 | No production source edited, no `.dev-flow` artifact edited | ✓ | `git status --porcelain` → `M .dev-flow/state.json`, `?? .dev-flow/2026-07-26-batch-63/` only; `git diff --numstat origin/main -- s19_app/` empty |
| 18 | Own prior review corrected where the code contradicted it | ✓ | §1 — all three addendum classes are document-derived (`apply.py:363`, `check.py:399`); my F1's "the tool's own findings" was imprecise |

---

## 10. Verdict

- [ ] OK to ship
- [x] **OK to ship with the listed mitigations applied first — CONDITIONAL on operator sign-off for F2**
- [ ] Block

### Gate conditions (all spec-level; none needs new scope, files, or increments)

| # | fold | discharges |
|---|---|---|
| **G-1** | **Operator-signed risk acceptance for F2**, with the numbers in the PR body (988 B/entry · ~6.3 GB · ~6.4 kB/region at K=200). Without a name on it the verdict reverts to BLOCKED. | F2 |
| **G-2** | Add **OB-4**: carry the **resident-memory** axis to `.dev-flow/BACKLOG.md`, noting that line 25's `_ByteBudget` remedy does not close it. | F2 |
| **G-3** | Narrow `AT-165`'s label to *"no producing class is wholly evicted by another class"*; extend `LLR-100.3`/`AT-167` so the notice **names the cut classes** and warns that later variants may be unrepresented; record the intra-class/cross-variant residual in `HLR-100`'s "does NOT claim" paragraph. | F1 |
| **G-4** | `LLR-101.2` → `^-?0x[0-9A-F]+$`; `AT-171` asserts that pattern, with `0x-…` as an added RED counterfactual; add the negative-width TC. | F3 · F8 |
| **G-5** | `AT-170` → *"when **composition** raises"*; delete or qualify `LLR-101.4`'s *"so an abort leaves no file"*. | F6 |
| **G-6** | Restore the checklist-twin AT (`AT-176`), or make `AT-168`'s fixture normatively carry both a change summary and a check result. | N-1 |

**Non-gating recommendations:** fold the cap-count assertion into `AT-166` (N-2); update
`flow_report_service.py:435`'s `Raises:` in increment 1 (F9); optionally carry the
temp-name + `os.replace` atomic write to BACKLOG (F6b).
