# batch-63 (RE-SCOPED) — Phase-1 pre-execution transcript (C-39)

> **BLUF: every threshold the D1/D2/D3 acceptance layer will be keyed on was EXECUTED on
> `031ca8d` before any requirement text was written. Three of the numbers the re-scoped spec
> carries were wrong or incomplete, and one design premise ("pin the writer") is insufficient.**

C-39 governs the numbers the gate itself is keyed on: a threshold computable before the
implementation exists **must** be executed and its transcript pasted, never predicted and never
inherited from a reviewer's prose. Everything below is output, not reasoning.

**Base:** `claude/batch-63-report-table-caps` @ `031ca8d` == `origin/main` (RC-1 re-verified).
**Host:** Windows, `os.linesep = '\r\n'`, Python 3.14, `sys.get_int_max_str_digits() = 4300`.
**Probe discipline:** every probe bounded and its temp tree deleted (the prior session's unbounded
100 000-entry probes exhausted host RAM and killed the machine). Counterfactuals run in `git archive`
exports, never the shared worktree (batch-62 cost an in-flight security review 4 spurious failures
that way).

---

## Summary of corrections to the re-scoped spec

| # | Spec said | Measured | Impact |
|---|---|---|---|
| C-1 | D3 undercount = **(lines − 1)** | **(lines − 2)** — 7/7 compositions | A cap derived from N−1 is off by one byte per document |
| C-2 | D3 golden-neutrality `assumed`, "must be EXECUTED" | **EXECUTED — neutral.** 116 passed in both arms | Claim promoted from assumed to measured |
| C-3 | D3 fix shape = "pin the writer" | ~~Insufficient alone; fix re-derived as one shared encoder~~ **— C-3 IS WRONG. SUPERSEDED BY M-6 BELOW.** The scope ruling was right: the fix is writer-only. | See M-6 |
| C-4 | D3 site = `report_service.py:1682` | **Two modules.** `flow_report_service.py:456` shares `_line_bytes`/`_ByteBudget` and gates emission on `fits()` | Blast radius doubles |
| C-5 | D1 projection "~559.7 GB" | Input triple (R, V, E) never stated, so it **cannot be re-derived** | Replaced with a measured per-hit constant |
| C-6 | D2 "4 301+ decimal digits is schema-legal" | True; boundary located exactly at **3572 hex digits** | Gives the AT a real boundary pair |

---

## M-1 / M-1b — D3: the undercount is N−2, not N−1

`_line_bytes` charges `+1` per line (`report_service.py:394`), so accounting = Σ(len) + N.
`"\n".join(lines)` emits **N−1** newlines, each written as CRLF = 2 B, so disk = Σ(len) + 2(N−1).
Undercount = **N − 2**.

M-1 reconstructed the line list from the written file; **M-1b instruments the real `_ByteBudget`**,
so the claim is about the allocator the code actually consults:

```
  entries  variants  lines N  accounted   on disk   delta    N-1    N-2
        2         1       74       2535      2607      72     73     72
       10         1       82       2993      3073      80     81     80
       10         2      121       4021      4140     119    120    119
       50         3      280      12009     12287     278    279    278

=== M-1b: real budget.used vs disk ===
  entries=10 variants=2 hexdump=False | N= 121 budget.used=   4021 on_disk=   4140 delta=  119 N-2=  119 match=True
  entries=10 variants=2 hexdump= True | N= 163 budget.used=   6907 on_disk=   7068 delta=  161 N-2=  161 match=True
  entries=40 variants=3 hexdump= True | N= 403 budget.used=  21741 on_disk=  22142 delta=  401 N-2=  401 match=True
```

7/7 compositions: `delta == N − 2` exactly, **including** compositions with hexdump sections (so
`_hexdump_section`'s internal `consume` is consistent with the rest). Both REV-5 lanes independently
wrote N−1; neither executed it. *A carried number is re-derived, not copied.*

## M-5 — D3: why "pin the writer" is not the whole fix

```
host os.linesep = '\r\n'   (CI is ubuntu-latest -> '\n')
lines N = 6   _line_bytes = 49

writer form                bytes   CR?  acc-disk  disk==acc-1
write_text (SHIPPED)          53  True        -4        False
write_bytes                   48 False         1         True
open(newline="")              48 False         1         True
open(newline='\n')            48 False         1         True
```

Two consequences the spec does not carry:

1. **Pinning the writer leaves the accounting 1 byte OVER** (`disk == acc − 1`). That is the safe
   direction and negligible in magnitude, but the artifact must say so rather than claim exactness.
2. **CI is structurally blind to D3.** `tui-ci` and `snapshot-regen` both run `ubuntu-latest`
   (`.github/workflows/tui-ci.yml:25,61`), where the *unpatched* writer already emits LF. So the
   undercount is **zero on CI** and an assertion of the form "the written file contains no CR" is
   **GREEN pre-fix on the platform the merge gate runs on** — a vacuous pass exactly where it is
   relied upon. Same shape as batch-61's "`tui-ci` is BLIND to snapshot drift".

**Therefore the acceptance criterion must not consult the host newline.** The invariant

```
len(LF.join(lines).encode("utf-8")) == _line_bytes(lines) - 1     -> True
```

holds on every platform *by construction*, **for N >= 1** (see M-6 — it is false at N = 0). Keying
the AT on this is testable everywhere. The RED counterfactual for the *writer* remains Windows-only
and the artifact must state that plainly instead of implying CI verifies it.

> ~~and making the writer and the accounting share ONE encoder so they cannot diverge~~
> **RETRACTED — see M-6.** This clause was mine, asserted from reasoning, and it is wrong.

## M-6 — I broke my own control one step after invoking it (C-3 RETRACTED)

The parallel Phase-1 `qa-reviewer` REFUTED the "one shared encoder" fix shape by implementing it in
an export and measuring it, and its refutation is **independently confirmed here**. C-39's own rider
says *re-measure the fold's OWN new thresholds, not only the inherited ones* — I applied that rule to
three inherited numbers (C-1, C-2, C-5) and then asserted a fresh DESIGN claim from reasoning in the
same document. Recorded as the batch's first process finding, against me.

**Why the shared encoder is worse than the defect it "fixes":** `generate_project_report` accounts in
~12 separate `emit()` batches (`report_service.py:1636-1679`), each calling `_line_bytes(batch)` and
adding to a running total. A correct accounting function must therefore be **partition-invariant**.
`len(LF.join(batch))` is not — it loses one byte per batch boundary:

```
  document: N=24 lines, on-disk (LF) = 181 bytes
                     partition  sum(_line_bytes)  sum(len(join))
                       1 batch               182             181
                     2 batches               182             180
    12 batches (composer-like)               182             170
                        uneven               182             177
```

`sum(_line_bytes)` is **182 under every partition**; `sum(len(join))` reads 170 against a true 181 at
composer-like granularity. The shipped `+1`-per-line form is partition-invariant *by construction*
and conservative by exactly **+1 byte** for the whole document. The qa-reviewer measured the same
thing end-to-end through the shipped surface: `budget.used` **11 bytes under the file** at 2/20/200
entries, delta constant — 11 being the boundary count of a 12-batch partition.

**Domain defect in the invariant, also caught by qa:** it is FALSE at N = 0.

```
  N=0  _line_bytes=  0  len(join)=  0  holds(jb == acc-1)=False
  N=1  _line_bytes=  1  len(join)=  0  holds(jb == acc-1)=True
  N=2  _line_bytes=  4  len(join)=  3  holds(jb == acc-1)=True
  N=3  _line_bytes= 11  len(join)= 10  holds(jb == acc-1)=True
```

**Validated fix shape (supersedes C-3): writer-only.** Leave `_line_bytes` exactly as shipped; add a
`report_bytes()` encoder and route BOTH writers through `write_bytes`. The scope ruling's original
"pin the writer" was right and my elaboration was the error.

**Terminology ruling (orchestrator).** The phrase I used — *"the writer and the accounting share ONE
encoder"* — carried two different designs and each Phase-1 lane read a different one. The qa lane
read it as `_line_bytes := len(encoder(lines))` and REFUTED that reading by measurement; the
architect lane's normative `LLR-102.2` keeps `_line_bytes` an independent function merely CONSTRAINED
to be an upper bound of the encoder. **Those two lanes agree on the design and disagree only on my
wording.** The requirement text must say "one encoder for the WRITERS; `_line_bytes` unchanged",
never "shared by the writer and the accounting".

## M-7 — BOTH lanes' "platform-independent invariant" is VACUOUS (orchestrator finding)

The two lanes proposed competing forms and argued about which is arithmetically valid at N = 0:

```
qa lane        : len(LF.join(lines).encode()) == _line_bytes(lines) - 1     (guarded to N >= 1)
architect lane : _line_bytes(lines) >= len(LF.join(lines).encode())         (universal, incl. N = 0)
```

Neither lane asked the question that decides a gate: **can it go RED on the UNFIXED tree?** Executed
against the shipped `_line_bytes` at `031ca8d` over a derived input set:

```
case                      N  _line_bytes  len(join)  qa: ==acc-1  arch: acc>=
empty                     0            0          0        False         True
one line                  1           23         22         True         True
table                     4           31         30         True         True
unicode                   3           23         22         True         True
wide                      2         4098       4097         True         True
random N=28              28          917        916         True         True

qa form  (N>=1 domain): RED cases on the UNFIXED tree = 0
arch form (all N)     : RED cases on the UNFIXED tree = 0
```

**Both are green pre-fix.** Both expressions are functions of `_line_bytes` and `"\n".join` ONLY, and
the D3 fix changes neither — so whatever they evaluate to after the fix, they already evaluate to
before it. As written, `AT-174` verifies nothing about D3 in either form.

This is the project's dominant defect class (the vacuous check) surfacing in the acceptance layer of
**two independent lanes at once**, in the batch whose founding thesis is that a document must not
assert what it does not honour. It survived both because the disagreement was framed as *which
predicate is valid* rather than *which predicate can fail*.

**RULING — re-key `AT-174` to the ENCODER, not to `"\n".join`:**

```
_line_bytes(lines) == len(report_bytes(lines)) + 1     for N >= 1
_line_bytes([])    == 0                                 and len(report_bytes([])) == 0
```

`report_bytes` does not exist on `031ca8d`, so the assertion **cannot bind pre-fix and is RED on
every platform including CI** — the same property that makes `AT-172`/`AT-173` load-bearing. It is
also strictly stronger as a pin than `>=`: changing `+1` to `+2` in `_line_bytes` turns it RED,
whereas `>=` stays green. That matters here specifically, because the C-26 reverse census found
`_line_bytes` has **zero** test references today, so its convention can currently be changed with a
fully green suite.

`AT-175` (no CR on disk) keeps the architect's label: **supplementary, Windows-only, explicitly NOT
verified by the merge gate.**

> ### THE M-7 RULING ABOVE IS REFUTED (Phase-2 qa lane, accepted by the orchestrator)
>
> The Phase-2 `qa-reviewer` was briefed to attack this ruling rather than adopt it, and it did. It
> built the minimal WRONG implementation — add `report_bytes`, leave `write_text` at `:1682` — and
> ran the ruled predicate against it:
>
> ```
> case                N  _line_bytes  len(rb)  ruled-predicate
> N=0 empty           0            0        0  PASS
> N=1 ascii           1            6        5  PASS
> N=3 table           3           30       29  PASS
> N=64 bulk          64         1378     1377  PASS
>   RED cases against the WRONG implementation: 0
> ```
>
> — on a tree that still writes `b'# report\r\n\r\n| a | b |\r\nrow'`.
>
> **The critique, which is correct:** *"cannot bind pre-fix" is a property of the SYMBOL, not of the
> DEFECT — the same argument would make `assert hasattr(rs, "report_bytes")` a D3 gate.* Confirmed
> independently by inspection: the predicate relates `_line_bytes` to `report_bytes`, and **both are
> pure functions of `lines`. The writer never appears in the expression**, so no value it takes can
> depend on how bytes reach the disk.
>
> **I diagnosed both lanes correctly and then authored a third vacuous form.** M-7 fixed the
> *bindability* of the assertion and left its *blindness to the writer* exactly where it was. That is
> three vacuous D3 acceptances in one batch, and the only one written by the orchestrator.
>
> **Re-classification:** `AT-174` is a **regression pin on the `+1` convention** — worth keeping,
> because the C-26 census found `_line_bytes` has zero test references and its convention can be
> changed today with a fully green suite — and it is **NOT a D3 gate**. It must be labelled as a pin.
>
> **What actually gates D3** (both survived the same probe, both RED correctly): the architect's
> `AT-172` encoder-mutation test, which monkeypatches the encoder and asserts **the written file
> follows** — the file is in the expression — and the qa lane's structural/AST census asserting that
> no accounting-sharing module writes in text mode.

## M-2 — D3 golden-neutrality: EXECUTED, and it holds

The spec flagged this `assumed` ("Both lanes asserted it; no lane measured it"). Two `git archive`
exports of `031ca8d`, arm B patched to `target.write_bytes("\n".join(lines).encode("utf-8"))`,
identical test selection — the observer set **derived** by grepping `generate_project_report`
callers rather than hand-listed (C-31):

```
ARM A (baseline, unpatched):  116 passed in 140.10s
ARM B (D3 writer fix):        116 passed in 137.05s
```

`tests/test_report_service.py` · `test_report_field_census.py` · `test_report_progress.py` ·
`test_report_symbol_escape.py` · `test_tui_report_seam.py` · `test_tui_report_view.py`.
Zero drift — `canonical_report_bytes` (`tests/conftest.py:1009`, `raw.replace(b"\r\n", b"\n")`)
does undo CRLF as claimed.

**Widened to the whole suite.** `pytest -q -m "not slow"` on the patched export:

```
3 failed, 2188 passed, 3 skipped, 21 deselected, 3 xfailed in 1303.19s (0:21:43)
29 snapshots passed.
```

No golden moved and no report/snapshot test failed. The three failures are **proven
environmental, not excused as such**: they were re-run in the UNPATCHED arm and fail identically
there in 0.58 s —

```
FAILED tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main
FAILED tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned
FAILED tests/test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff
3 failed in 0.58s
```

— all three diff against `main` and a `git archive` export carries no `.git`
(`RuntimeError: could not locate the repository root from the s19_app package`). They are
unrunnable in an export by construction, in either arm. **Phase-3 obligation:** they must be run
in the real worktree, where they can actually execute, before the writer change is called
non-regressive.

**Self-correction on my own probe (C-31 applied to me):** I derived the observer set from
`generate_project_report` callers, which omits `tests/test_flow_report_service.py` — an observer of
the *other* D3-affected writer. It is out of scope for this arm (which patches only
`report_service`) but it is in scope for C-4 below, and the omission is recorded rather than
quietly widened.

## C-4 — D3's blast radius is two modules, not one

Every writer in `s19_app/` was enumerated (`grep -rn "write_text(\|open(.*'w'"`), then cross-checked
for byte accounting:

| module | writer | has a `_ByteBudget`? | D3 applies? |
|---|---|---|---|
| `report_service.py` | `:1682` `write_text` | yes (`fits()` gates hexdump blocks only) | **YES** |
| `flow_report_service.py` | `:456` `write_text` | **yes — imports `_ByteBudget`/`_line_bytes` from `report_service` (`:72-73`) and `fits()` at `:310` GATES whether a section is emitted at all** | **YES, and more load-bearing** |
| `diff_report_service.py` | `:1393`, `:2063` `write_text` | no | no — CRLF on disk, but no accounting to be wrong against |

In `flow_report_service._compose`, `put()` **drops a section and records it as truncated** when
`fits()` says no (`:308-315`). An undercounting allocator there decides emission, not just a cap.

## M-3 / M-3b — D2: reproduced, located, and bounded

```
generate_project_report -> ValueError: Exceeds the limit (4300 digits) for integer string conversion
  raised at report_service.py:996  ->  f"| {entry.address_end - entry.address_start} "
  files left in reports/: []
```

**Boundary, executed:**

```
  3570 hex digits -> hex OK | decimal OK (4299 digits)
  3571 hex digits -> hex OK | decimal OK (4300 digits)
  3572 hex digits -> hex OK | DECIMAL RAISES (ValueError)
  --> first raising width: 3572 hex digits
```

**Schema-legality through the shipped ingest path** (`_ADDRESS_RE = ^0x[0-9A-Fa-f]+$`):

```
      8 hex digits | match= True | _parse_address accepted= True | issues=0
   3571 hex digits | match= True | _parse_address accepted= True | issues=0
   3572 hex digits | match= True | _parse_address accepted= True | issues=0
   3672 hex digits | match= True | _parse_address accepted= True | issues=0
```

So the crashing address is reachable from a change file, not only by hand-constructing a dataclass.
The spec's "the obvious suspect is innocent" is confirmed: `f"0x{v:08X}"` renders fine at the
raising width (hex is exempt from the digit limit); only the decimal `Length` column raises.

> ### CORRECTION (Phase-2 architect MAJ-1, verified by the orchestrator) — D2 does NOT crash the tool
>
> The probe above calls `generate_project_report` **directly, bypassing the shipped handler**, so it
> measures the service, not the surface. `s19_app/tui/app.py:4034` **catches** it:
>
> ```python
> except ValueError as exc:
>     self._log_report_event("project", project_dir.name, "-", f"rejected: {exc}", ok=False)
>     self.call_from_thread(self.set_progress, 0)
>     self.call_from_thread(self.set_status, f"Report rejected: {exc}")
>     return
> ```
>
> **At the shipped surface D2 is a report DENIAL, not a crash** — and worse in a way the "crash"
> framing hides: the failure lands in the **operator-input-rejection** branch, the same branch that
> reports genuine domain errors, and leaks a CPython internals string
> (`…use sys.set_int_max_str_digits() to increase the limit`) into the status line. An internal
> failure is presented to the operator as though their input was invalid.
>
> This is C-35 applied to me: I executed the transform but not the SURFACE. My "generate_project_report
> -> ValueError" transcript is accurate for what it ran; the word "CRASHES" in the scope ruling and in
> my summary of it is not accurate at the shipped surface. **Consequence for the scope ruling's own
> justification:** it argued the split was worth it because "two of them hang or crash the tool today"
> — D1 does, D2 does not. The requirement's observable outcome must be written against the denial +
> misclassification, not against a crash.

**Two properties the spec does not record, both relevant to the fix:**
- **Fail-closed today.** `reports/` is left with **no file** — the raise happens during line
  composition, before the single `write_text` at the end. Whatever the fix does, it must not
  regress this into a partial document.
- **Boundary pair for the AT:** 3571 hex digits survives / 3572 raises. Both must bite.

## M-4 — D1: the cost law, measured on a bounded grid

Ceiling enforced at 200 000 hits; the fixture the spec says "building it is what crashes" was never
built.

```
   R    V      E     R*V*E     lines      peak B    B/hit
   1    1    500       500       504       46831     93.7
   2    1    500      1000      1006       89425     89.4
   4    1    500      2000      2010      174581     87.3
   1    2    500      1000      1004       93971     94.0
   1    4    500      2000      2004      186299     93.1
   1    1   1000      1000      1004       93971     94.0
   1    1   2000      2000      2004      186299     93.1
   4    4   2000     32000     32010     2787589     87.1

=== product-law check ===
  R 1->2         lines x2.00   peak x1.91
  R 2->4         lines x2.00   peak x1.95
  V 1->2         lines x1.99   peak x2.01
  V 2->4         lines x2.00   peak x1.98
  E 500->1000    lines x1.99   peak x2.01
  E 1000->2000   lines x2.00   peak x1.98
```

O(R×V×E) **confirmed by execution** on all three axes independently: one line per
(region × variant × entry), **87–94 B resident per hit** (`tracemalloc`). Any projection now
extrapolates from a measured constant.

**C-5 — the spec's headline number cannot be re-derived.** "~559.7 GB, ~1 283 min" is stated without
its input triple (R, V, E), so a reader cannot reproduce it. Under this batch's own rule that a
carried number is re-derived rather than copied, the requirement artifact must state the triple it
assumes and the measured B/hit it multiplies, or drop the figure. It is quoted here as provenance,
**not adopted as a threshold.**

## C-26 reverse census — the touched symbols

`grep -rl <symbol> tests/`:

| symbol | test files | note |
|---|---|---|
| `_addendum_lines` | **0** | D1's subject has no direct test |
| `_line_bytes` | **0** | D3's accounting primitive is untested as a unit |
| `_modifications_lines` | 0 | D2's crash site, exercised only through the report |
| `_checklist_lines` | 0 | the "checklist twin" |
| `_ByteBudget` | 1 | `test_report_field_census.py` |
| `REPORT_MAX_TOTAL_BYTES` | 2 | `test_report_service.py`, `test_flow_report_service.py` |

Nothing pins `_line_bytes`'s value, so today the +1 convention can be changed with a green suite.
That is the same shape as batch-62's B-2 (`REPORT_CELL_CHARS` appeared only as an argument, never
with a boundary pair).

---

## Environment gotcha found while running these (carry to Phase 3)

`git archive` exports under the session scratchpad hit the Windows **MAX_PATH** 260-char limit:
`…/scratchpad/export_m2_patched/s19_app/tui/services/variant_execution_service.py` is 261 chars and
imports fail with a misleading `ModuleNotFoundError: No module named
's19_app.tui.services.variant_execution_service'` even though the file is present and byte-correct.
The baseline path (`export_m2`, 8 chars shorter) is 253 and works. Diagnosed by diffing the two
exports (exactly one line differed) and re-testing the import at a short path. **Export
counterfactuals must use a short root** (`C:/Users/<u>/AppData/Local/Temp/claude/b63/{a,b}`).

Also: this environment's shell heredoc consumes one level of backslash escaping, which silently put
a real newline inside a Python source string on the first patch attempt. Patch scripts are written
to disk and invoked by path, never piped through a heredoc.
