# batch-64 — QA catalog (Phase 1, qa lane)

> **Deliverable of the QA lane.** Corpus, validation methods, AT catalog with every reddening
> mutation EXECUTED, self-application verdict, blockers.
> Layer A (`TC-NNN`) is declared **N/A with reason** — argued in §7, not assumed.

---

## 0. BLUF

**The corpus is SIX, not five — and the sixth was found by executing the candidate control, not by
reading batch-63's summaries.** `AT-172b` (`tests/test_report_document_bytes.py:208-221`) shipped and
merged in batch-63 asserting `raw == rs.document_bytes(raw.decode("utf-8"))`, and
`document_bytes(text)` is `text.encode("utf-8")` (`s19_app/tui/services/report_service.py:440`). The
predicate is therefore `raw == raw.decode("utf-8").encode("utf-8")` — **a tautology for every valid
UTF-8 byte string, on every platform, pre-fix and post-fix**. Its own docstring claims *"This is the
clause that fails on a text-mode writer wherever `os.linesep != LF`"*; executed, that claim is false
(§1.6). It passed both Phase-1 lanes, three Phase-2 reviews, two post-0-HIGH fold rounds, and the
postmortem that counted the vacuous acceptances.

**Discrimination verdict: C-40 discriminates, but only with TWO limbs.** A single-limb C-40 (the
"subject never appears in the expression" form the operator's `BACKLOG.md` ruling states) flags
**4 of 6** and misses `AT-165` and `AT-193b` — the two the operator explicitly ruled must be ABSORBED
into it. Executed in §3.3. This is a direct input to the architect lane's control text: **if C-40 is
drafted with the one-limb wording currently in `BACKLOG.md`, AT-B64-01 goes RED.**

**Three findings block the Phase-1 gate as currently specified** (§9): AT-B64-05's predicate is
unsatisfiable as written; AT-B64-10's predicate is RED pre-batch on 9 ids that batch-64 is not
chartered to fix; and two carried counts in batch-64's own Phase-0 artifacts are wrong.

**Load-bearing:** AT-B64-01, AT-B64-02, AT-B64-03, AT-B64-09, AT-B64-10.
**Weak (presence-shaped, kept only as boundary complements):** AT-B64-05, AT-B64-07, AT-B64-08.
**Bookkeeping, not acceptance:** AT-B64-11.
**Unsatisfiable as scoped, needs re-scoping before it can be authored:** AT-B64-04 (§9.3).

---

## 1. The corpus — POSITIVE group (known-vacuous predicates)

Every entry is transcribed verbatim from disk with a `file:line` citation. The postmortem's claim of
**five** is confirmed correct *for what batch-63 knew*; a sixth was found here.

### V-1 — Phase-1 qa lane, the `== acc-1` form

`.dev-flow/2026-07-26-batch-63/00b-measurements-rescoped.md:149`

```
qa lane        : len(LF.join(lines).encode()) == _line_bytes(lines) - 1     (guarded to N >= 1)
```

### V-2 — Phase-1 architect lane, the `acc >= len(join)` form

`.dev-flow/2026-07-26-batch-63/00b-measurements-rescoped.md:150`

```
architect lane : _line_bytes(lines) >= len(LF.join(lines).encode())         (universal, incl. N = 0)
```

Normative restatement at `01-requirements-rescoped-architect.md:266` and `:359` (`AT-174`).

### V-3 — the orchestrator's M-7 replacement, keyed on `report_bytes`

`.dev-flow/2026-07-26-batch-63/00b-measurements-rescoped.md:181-182`

```
_line_bytes(lines) == len(report_bytes(lines)) + 1     for N >= 1
_line_bytes([])    == 0                                 and len(report_bytes([])) == 0
```

Refuted in-place at `:212-216`, verbatim:

> **The critique, which is correct:** *"cannot bind pre-fix" is a property of the SYMBOL, not of the
> DEFECT — the same argument would make `assert hasattr(rs, "report_bytes")` a D3 gate.* Confirmed
> independently by inspection: the predicate relates `_line_bytes` to `report_bytes`, and **both are
> pure functions of `lines`. The writer never appears in the expression**

### V-4 — `AT-165`, shaped to the concatenation rather than to the evidence

`.dev-flow/2026-07-26-batch-63/01-requirements-rescoped-consolidated.md:171`

```
| `AT-165` | With 200 attacker-supplied modification entries and >=1 validation issue in the same
region, **the issue still appears**. | Revision 2's single per-region cap: 0 of 5 survive (executed).
RED on every platform. |
```

Refuted by execution at `02-regate-discharge-qa.md:137-143`:

```
   attacker mints 400 CHG-ADDRESS-SYNTAX in v1; v2 and v3 each carry one CHG-COLLISION
   rendered summary-issue hits: 200
   CHG-ADDRESS-SYNTAX (attacker-minted): 200
   CHG-COLLISION      (tool finding)   : 0
   variants represented in output      : ['v1']
   AT-165 'every producing class is represented' -> GREEN
```

and independently at `02-regate-security.md:81-83`, `:98`, `:103` (*"`AT-165`'s predicate is weaker
than its label"*).

### V-5 — `AT-193b`, the positive control shaped to the DETECTOR

The vacuous form is the **first** version, committed at `47ac15a` and replaced at `11b79a9`. Retrieved
with `git show 47ac15a:tests/test_report_document_bytes.py`, lines 291-303 of that blob:

```python
    offending = (
        'p.write_text("x")',
        'open(p, "w")',
        'io.open(p, "wt")',
        'codecs.open(p, mode="a")',
        'open(p, "x")',
    )
    clean = (
        'p.write_bytes(b"x")',
        'open(p, "wb")',
        'io.open(p, "rb")',
        'open(p, "r")',
    )
```

The shipped replacement (`tests/test_report_document_bytes.py:314-340`) carries its own diagnosis in a
comment, verbatim:

```python
    # Shaped to the RULE ("shall not encode or newline-translate on its own"),
    # not to the detector. The first version of this list was shaped to the
    # detector and therefore certified a completeness the detector did not have:
    # it omitted `p.open("w")`, which is this repo's own house idiom for text
    # writes and which the detector could not see.
```

Delta: 5 -> 11 offending, 4 -> 7 clean. The omitted-and-load-bearing member is `p.open("w")`.

### V-6 — `AT-172b`, a tautology. NEW — found by this lane, not previously recorded.

`tests/test_report_document_bytes.py:208-221` (shipped, merged at `c473152`, live on `main`):

```python
def test_at172b_the_unpatched_report_is_exactly_the_encoder_output(tmp_path: Path) -> None:
    """AT-172 / TC-471 — the file equals ``document_bytes`` of the joined document.

    Platform-independent: it never consults ``os.linesep``. This is the clause
    that fails on a text-mode writer wherever ``os.linesep != LF``.
    """
    path = _one_variant_report(tmp_path)
    raw = path.read_bytes()

    assert raw == rs.document_bytes(raw.decode("utf-8")), (
        "the written bytes are not the encoder's output for their own text — "
        "a newline translation happened at write time."
    )
    assert CR.encode() not in raw or os.linesep == LF
```

and `s19_app/tui/services/report_service.py:440`:

```python
    return text.encode("utf-8")
```

Executed (`at172b_tautology.py`, output pasted verbatim):

```
LF host    PRE-FIX  text mode  bytes=b'# report\n\n| a | b |\nrow'                 AT-172b=True  companion=True
LF host    POST-FIX byte mode  bytes=b'# report\n\n| a | b |\nrow'                 AT-172b=True  companion=True
CRLF host  PRE-FIX  text mode  bytes=b'# report\r\n\r\n| a | b |\r\nrow'           AT-172b=True  companion=False
CRLF host  POST-FIX byte mode  bytes=b'# report\n\n| a | b |\nrow'                 AT-172b=True  companion=True

AT-172b RED cases over {pre,post} x {LF,CRLF}: 0
Only way to redden it: write bytes that are not valid UTF-8.
```

**Reading.** The docstring's claim is false: the main assertion is GREEN in all four cells. The file's
own bytes are decoded and re-encoded, so the round trip is an identity and the writer is eliminated
from the expression by construction. Only the *companion* line (`CR.encode() not in raw or
os.linesep == LF`) can go RED, and only on a CRLF host — i.e. never on CI, and it duplicates `AT-175`,
which `REQUIREMENTS.md:4857` explicitly labels **NOT verified by the merge gate**.

Contrast `AT-173b`'s second clause (`tests/test_flow_report_service.py:497`), which is sound because
it compares the file against an *independently composed* document rather than against its own decode:

```python
    assert raw == frs.document_bytes(compose_flow_report(_state(), _AT))
```

`AT-172b` has no such clause. **This is a live defect on `main`, out of batch-64's scope, and is
carried to §9.6.**

---

## 2. The corpus — NEGATIVE control group (sound predicates the rule must NOT flag)

Building the corpus only from cases the rule already catches is the exact defect P-6 names, and
batch-63 committed it while hunting vacuity (V-5). This group is therefore not optional.

| id | predicate | cite | why it is sound |
|---|---|---|---|
| **S-1** | `AT-172` — monkeypatch `document_bytes` to a sentinel; assert `path.read_bytes() == sentinel` | `tests/test_report_document_bytes.py:187-206` | the file is in the expression; RED pre-fix on every platform, CI included |
| **S-2** | `AT-173` — the same seam for `write_flow_report`, patching `flow_report_service.document_bytes` | `tests/test_flow_report_service.py:448-480` | the patch target is the binding in the module under test; the file is in the expression |
| **S-3** | `AT-173b` clause 2 — `raw == frs.document_bytes(compose_flow_report(_state(), _AT))` | `tests/test_flow_report_service.py:497` | compares the file to an **independently composed** document, so the round trip is not an identity |
| **S-4** | `AT-193` — AST census: no accounting-sharing module writes in text mode, module set derived from the import graph and asserted non-empty | `tests/test_report_document_bytes.py:274-298` | C-31-compliant derived set + non-emptiness guard; RED pre-fix on every platform |
| **S-5** | `TC-441` / `LLR-100.2` — inject a counting iterable, assert `consumed <= 3K + eps` | `01-requirements-rescoped-consolidated.md:156-158`; probe `01-requirements-rescoped-architect.md:483-486` | separates `cap,NO-break` from `cap+break`, which the resource-ratio form could not: `scanned` measured **201** at `E = 500 / 2000 / 8000` |
| **S-6** | `AT-174b` — `sum(_line_bytes(b) for b in partition) == _line_bytes(whole)` | `tests/test_report_document_bytes.py:241-266` | **the sharpest control.** The writer does *not* appear in it — yet it is sound, because its declared subject is `_line_bytes`'s `+1` convention, and that IS in the expression. Explicitly re-classified as a PIN, not a D3 gate (`01-requirements-rescoped-consolidated.md:285`) |

S-6 exists to falsify a lazy C-40. A control keyed on *"the writer must appear"* rather than *"the
declared subject must appear"* flags S-6 and becomes a false-positive machine. Executed in §3.4.

---

## 3. The discriminator, built and executed

### 3.1 C-40 stated as a mechanical predicate

> Given an acceptance predicate `P` and the change `D` it is offered as the gate for, with
> `subject(D)` = the artifact or symbol `D` modifies:
>
> - **LIMB 1 — subject-reference.** FLAG `P` if `P`'s value is **invariant under `D`** — i.e. `P`
>   evaluates identically on the pre- and post-change trees for every input in its domain.
>   Operationally: `subject(D)` does not appear in `P`'s expression.
> - **LIMB 2 — domain-shape.** FLAG `P` if `P` quantifies over a set, and that set was drawn from the
>   **implementation** `P` certifies rather than from the **rule** `P` states.
>
> Discharge for both: name the mutation that reddens `P`, and **execute it**.

Limb 1 is mechanisable and was mechanised. Limb 2 is **inspection** — honestly labelled as such in
§4 — because deciding "was this set drawn from the rule or from the code?" requires reading the rule.

### 3.2 LIMB 1 executed — `c40_probe.py`

The probe models the actual change under test (text-mode writer -> byte-mode writer) on both an LF and
a CRLF host and evaluates each predicate under both writers. `T->T` means "same value pre- and
post-fix", i.e. invariant, i.e. cannot gate the change.

```
predicate                                                                    LF host   CRLF host  VERDICT
----------------------------------------------------------------------------------------------------------------
V-1 qa lane   len(LF.join(lines).encode()) == _line_bytes(lines) - 1   [N>=1]      T->T        T->T  FLAG (invariant under the writer)
V-2 arch lane _line_bytes(lines) >= len(LF.join(lines).encode())       [all N]      T->T        T->T  FLAG (invariant under the writer)
V-3 M-7 ruling _line_bytes(lines) == len(report_bytes(lines)) + 1      [N>=1]      T->T        T->T  FLAG (invariant under the writer)
```

This is the same result batch-63 reached by hand at `00b-measurements-rescoped.md:157-166`
(`RED cases on the UNFIXED tree = 0` for both lane forms), re-derived independently here rather than
copied — the batch-63 rule *a carried number is re-derived, not copied*.

### 3.3 Both arms, and the mutation that reddens each — `c40_arms.py`

```
=== C-40 AS SPECIFIED (both limbs) ===
POSITIVE ARM  flagged 6/6   -> GREEN
   V-1  FLAG  qa lane  len(join)==_line_bytes-1  [N>=1]        00b-measurements-rescoped.md:149
   V-2  FLAG  arch lane _line_bytes>=len(join)   [all N]       00b-measurements-rescoped.md:150
   V-3  FLAG  M-7      _line_bytes==len(report_bytes)+1        00b-measurements-rescoped.md:181-182
   V-4  FLAG  AT-165   every producing class is represented    01-requirements-rescoped-consolidated.md:171
   V-5  FLAG  AT-193b  offending list (pre-reshape)            47ac15a:tests/test_report_document_bytes.py:291-295
   V-6  FLAG  AT-172b  raw == document_bytes(raw.decode())     tests/test_report_document_bytes.py:208-221

=== MUTANT: limb-2 deleted ===
POSITIVE ARM  flagged 4/6   -> RED
   V-1  FLAG  ...
   V-2  FLAG  ...
   V-3  FLAG  ...
   V-4  miss  AT-165   every producing class is represented    01-requirements-rescoped-consolidated.md:171
   V-5  miss  AT-193b  offending list (pre-reshape)            47ac15a:tests/test_report_document_bytes.py:291-295
   V-6  FLAG  AT-172b  ...
```

**This is the single most important number in this document.** `BACKLOG.md:34` states C-40's rationale
in one-limb form — *"the writer never appeared in the expression"*. Encoded that way, C-40 misses
`AT-165` and `AT-193b`, which are precisely the P-6/P-7 absorption content the operator ruled must
live **inside** C-40. **The architect lane must draft C-40 with both limbs or AT-B64-01 goes RED.**

### 3.4 Negative arm, and its reddening mutant

```
=== NEGATIVE ARM (C-40 as specified) ===
   S-1  ok    AT-172   file bytes == patched-encoder sentinel
   S-2  ok    AT-173   same seam, flow writer, normative target
   S-3  ok    AT-173b clause2 raw == db(compose_flow_report())
   S-4  ok    AT-193   AST census, import-graph-derived + guarded
   S-5  ok    TC-441  counting iterable: scanned==201 at E=500/2000/8000
   S-6  ok    AT-174b _line_bytes partition-invariance PIN
false positives 0/6   -> GREEN

=== NEGATIVE-ARM MUTANT: limb 1 keyed on 'the WRITER' instead of 'the subject' ===
   S-6 AT-174b's subject is _line_bytes's +1 convention, NOT the writer.
   The writer does not appear in it -> FLAGGED -> false positives 1/6 -> RED
```

### 3.5 Discrimination against C-10 / C-31 / C-39 — the case each does not catch

Quoted from the encoded text, not from memory.

| control | encoded at | what it mutates | the case it misses |
|---|---|---|---|
| **C-10** | `~/.claude/commands/dev-flow.md:54` — *"a green AT is not proof it exercises the surface"*, non-default values + one AT per policy branch | the **code / the driven value** | **V-1, V-2, V-3, V-6.** §3.2 executed the code mutation (text-mode -> byte-mode writer) and all four are `T->T`. C-10 mutates the thing under test; these predicates do not reference it, so the mutation is silent. |
| **C-31** | `dev-flow.md:57` — *"when a test certifies a UNIVERSAL, its INPUT SET is itself an oracle … derived from the code … never hand-listed"* | the **input set** | **V-1, V-2, V-3.** `01-requirements-rescoped-architect.md:374` records the input set as derived by enumerating every `_line_bytes` call site — C-31 fully discharged — and `:394` still reports the predicate green on 6/7 (7/7 for the `>=` form). A derived set over the wrong expression is still the wrong expression. **C-31 does catch V-5** (`AT-193b`'s hand-listed offending tuple), which is why V-5 is the weakest positive-arm member and is retained rather than leaned on. |
| **C-39** | `dev-flow.md:147` — *"a threshold that CAN be computed before the implementation exists MUST be, and its transcript recorded"* | the **numbers the gate is keyed on** | **V-4, V-6.** Neither carries a threshold. `AT-165` names the constant, never its value (`01-requirements-rescoped-architect.md:659` records this as discharged); `AT-172b` carries no number at all. C-39 has nothing to bite on. |

**No existing control catches V-6.** It survives C-10 (invariant under the code change), C-31 (no set
to derive), and C-39 (no threshold). It was found only by asking C-40's question. That is the
discrimination arm's evidence, and it is empirical rather than argued.

---

## 4. Validation method per requirement

| story | deliverable | method | justification |
|---|---|---|---|
| **US-B64-1** (C-40) | control block in `~/.claude/commands/dev-flow.md` | **Test** (executable: `c40_arms.py` over the labelled corpus, pass/fail table printed) + **Inspection** for limb 2 | The positive/negative arms are a scripted application of the encoded rule to a fixed corpus with a printed table. Limb 2 cannot be mechanised — deciding "drawn from the rule or from the implementation?" requires reading the rule — so it is `inspection`, and each limb-2 verdict carries a `file:line` citation to the refutation that established it. |
| **US-B64-2** (C-41) | control block, same file | **Demo** (positive arm: apply the encoded text to each recorded occurrence, paste the verdict) + **Test** (boundary grep over the added block) | The boundary predicate is a grep whose output is pasted; the positive arm is a walkthrough because each occurrence is prose, not an expression. |
| **US-B64-3** (C-42) | new control in `docs/engineering-rules.md` | **Test** (mechanic-naming table over the s19_app instances) + **Test** (complement grep) | Each instance has an executable reproduction available in-repo (§5, AT-B64-06) — the SVG mechanic was reproduced live at 0/29 vs 29/29. Do **not** settle for inspection where a reproduction exists. |
| **US-B64-4** (`VERIFY.md`) | section extension | **Test** (de-identification grep) + **Analysis** (discrimination against the pre-existing text) | AT-B64-09 is an argument about what two texts do and do not cover; it is `analysis`, supported by the executed 0/29 counterexample. Labelled honestly rather than dressed as a test. |
| **US-B64-6** (lineage) | memory record update | **Test** (bidirectional union-grep census, executed at RC-1 and re-executed post-batch) | Fully mechanical. Already executed pre-batch in §5 (AT-B64-10) and it found a pre-existing gap. |
| **all out-of-VCS files** | 3 files | **Inspection** (SHA256 + line count before/after) | Only method available: no git history, no CI, no diff review. This is bookkeeping, not acceptance — labelled as such. |

---

## 5. AT catalog

Ids are the orchestrator's fixed registry with per-id semantics. Every entry states the mutation that
reddens it and reports the **executed** result.

---

### AT-B64-01 — C-40 positive arm

- **Observable.** C-40, applied as written to the six known-vacuous predicates V-1..V-6, flags all six.
- **Executed.** §3.3, `6/6 -> GREEN`.
- **Reddening mutation (EXECUTED).** Delete limb 2 from C-40's text. Result: `4/6 -> RED`. Output
  pasted at §3.3.
- **Second reddening mutation (EXECUTED).** Add a sound predicate to the positive corpus — moving S-6
  into the positive group drops the arm to `6/7 -> RED`, since C-40 correctly does not flag it.
- **Does the predicate reference the subject under test?** **Yes.** The subject is *the encoded C-40
  text*; the arm's value is a function of that text (deleting a limb changes the count). It is not a
  function of "does the string appear in the file".
- **Verdict: LOAD-BEARING.** It already went RED once during authoring, on a real mutation.
- **Dependency.** Cannot be run until the architect lane's C-40 text exists. The harness and corpus are
  complete now; only the rule text is pending.

### AT-B64-02 — C-40 negative arm

- **Observable.** C-40, applied to S-1..S-6, flags none.
- **Executed.** §3.4, `false positives 0/6 -> GREEN`.
- **Reddening mutation (EXECUTED).** Key limb 1 on *"the writer"* rather than on *"the declared
  subject"*. Result: S-6 flagged, `1/6 -> RED`. Output pasted at §3.4.
- **Does the predicate reference the subject under test?** **Yes** — same argument as AT-B64-01.
- **Verdict: LOAD-BEARING.** S-6 is a genuine trap and the mutant hits it.

### AT-B64-03 — C-40 discrimination against C-10 / C-31 / C-39

- **Observable.** For each of C-10, C-31, C-39: a **named** corpus member that control does not catch,
  with the evidence that it does not.
- **Executed.** §3.5 table. C-10 misses V-1/V-2/V-3/V-6 (executed code mutation, §3.2, all `T->T`);
  C-31 misses V-1/V-2/V-3 (its derivation was discharged and the predicate stayed green,
  `01-requirements-rescoped-architect.md:374` + `:394`); C-39 misses V-4/V-6 (no threshold present).
  **V-6 is missed by all three** and is the strongest single item.
- **Reddening mutation (EXECUTED).** Attempt the same table for **C-35** (draft-time execution probe,
  `dev-flow.md:145`). C-35 *does* catch V-6: running the transform over a real input is exactly the
  `at172b_tautology.py` probe, which is how V-6 was found. So the row cannot be filled and the arm
  goes RED against C-35. That is the arm behaving correctly — it distinguishes a control C-40
  genuinely extends from one that already covers the case.
- **Honest consequence, flagged for the architect lane.** C-40's discrimination against C-35 is
  **weaker than against C-10/C-31/C-39**. C-40's contribution over C-35 is that C-35 requires running
  the *product's* transform over a real input, while C-40 asks whether the *predicate* moves when the
  subject moves — V-1/V-2/V-3 survive C-35 because there is no product transform to run. State this in
  the control text; do not claim C-40 is orthogonal to C-35 when it is not.
- **Verdict: LOAD-BEARING, and it produced a finding against its own batch.**

### AT-B64-04 — C-41 positive arm over the recorded emitted-encoding occurrences

- **Observable as specified** (`01-requirements.md:64`): *"applied to the ~9 recorded occurrences
  across batches 61-63, each one flagged."*
- **BLOCKED — the scope and the count are both wrong.** Enumerated from the primary records:

| # | occurrence | batch | cite |
|---|---|---|---|
| 1 | prototype escaped for the wrong grammar; `MarkdownIt("gfm-like")` with linkify on autolinked a bare URL and `~~x~~` struck a ledger row | 60 | `memory/feedback_assert_emitted_encoding.md`, occurrence 1 |
| 2 | 5 self-inflicted assert bugs from asserting the doc's vocabulary rather than emitted text (`write_out` vs `WRITE-OUT`) | 60 | same, occurrence 2 |
| 3 | snapshot attribution predicate returned **0/19**; SVG emits `&#160;` entities | 61 | same, occurrence 3 |
| 4 | `&` unescaped so `&vert;` forges a table fragment with every token still `text` | 62 | `BACKLOG.md:20` |
| 5 | amendment naming `Cc`/`Cf` that missed `U+2028` (`Zl`) | 62 | `BACKLOG.md:20` |
| 6 | source-line regex guard false-positived on an implicitly-concatenated f-string; fixed with AST | 62 | `BACKLOG.md:20` |
| 7 | `'](' not in note` failed against a **correct** implementation; emitted form is `\](` | 62 | `BACKLOG.md:20` |
| 8 | `chk_rows = -1` probe; heading emitted as a Mode-B code span `` `chk.json` `` | 63 | `memory/project_batch_63_report_bounds.md:61-64` |

  **True count = 8, spanning batches 60-63.** The three carried figures disagree with each other and
  with the enumeration: `BACKLOG.md:20` says *"~7th occurrence over 3 batches"* (correct at
  batch-62 close); `BACKLOG.md:36` and `01-requirements.md:64` say *"~9 … across batches 61-63"*;
  `MEMORY.md` says *"8+ occurrences (5 in batch-63 alone)"*. The *"5 in batch-63 alone"* figure
  double-counts: `project_batch_63_report_bounds.md:61-64` lists five but two of them are explicitly
  *"the inherited batch-61 NBSP and batch-62 `"](" not in note`"*, and two more (`interior?` column,
  ascending-byte-run probe) are **predicate-must-test-its-label** instances, not emitted-encoding
  instances. Batch-63 contributed **one** new P-3 occurrence.
- **Required re-scope.** AT-B64-04 must read: *"applied to the 8 enumerated occurrences across
  batches 60-63"*. As written it excludes batch-60, which holds 2 of the 8, and asserts a count that
  cannot be reproduced.
- **Reddening mutation (EXECUTED, on the corpus).** Drop occurrence 7 (`'](' not in note`) from the
  set: C-41 as ruled says *"never a character list, a human-readable rendering, or the spec's own
  vocabulary"* — 7 is the only member where the predicate was written against a **character list**
  specifically, so removing it leaves that clause of C-41 with no supporting case and the arm's
  clause-coverage goes RED.
- **Does the predicate reference the subject under test?** **Yes**, once re-scoped — it is a function
  of C-41's clauses against a fixed set.
- **Verdict: UNSATISFIABLE AS WRITTEN. Blocker, §9.3.**

### AT-B64-05 — C-41 stack-free boundary

- **Observable as specified** (`01-requirements.md:66-68`): *"the encoded global text contains **no**
  stack-specific identifier (no `markdown-it`, `&#160;`, `Rich`, `Textual`, `SVG`, `AST`)."*
- **BLOCKED — unsatisfiable against the whole file, and the term list is wrong.** Executed against the
  pre-batch `~/.claude/commands/dev-flow.md`:

```
   markdown-it  0
   &#160;       0
   &vert;       0
   Rich         1      <- FALSE POSITIVE of my own harness: case-insensitive match inside "enrich".
   Textual      3         Case-sensitive word-boundary re-run: Rich = 0
   SVG          0
   AST         11      <- 11 is case-insensitive ("last", "past"). Word-boundary: AST at :57 (C-31)
   s19          0
   a2l          4
```

  Word-boundary, case-sensitive re-run:

```
--- Textual ---   149:Textual  149:Textual  202:Textual
--- a2l ---       145:a2l      150:A2L      176:a2l
--- AST ---       57:AST
```

  Line 202 is **normative**: *"Layer B — behavioral (black-box) acceptance: exercise the system as the
  user — Textual Pilot end-to-end (`App.run_test()`) …"*. Lines 145/150/176 are project examples inside
  C-35/C-17/C-27 origin notes. So a whole-file predicate is RED before batch-64 writes a word.
- **Required re-scope, two changes.** (a) Scope the predicate to **the added C-41 block only**, not the
  file. (b) **Remove `AST` from the forbidden list** — `dev-flow.md:57` already uses *"walk the AST"*
  inside C-31 as a stack-free technique; keeping it would prevent C-41 from saying "prefer a structural
  parse over a substring match", which is C-41's own discharge.
- **Note against myself.** My first harness lacked word boundaries and reported `Rich = 1` and
  `AST = 11`. That is the same defect `PLAN.md:76` records for the `TC-401` census, reproduced here and
  caught by re-running with boundaries. Recorded rather than quietly fixed.
- **Reddening mutation (EXECUTED).** Run the corrected harness against the *project* leg's intended
  content (`markdown-it`, `&vert;`) pasted into a scratch copy of the global block -> 2 hits -> RED.
  Run it against the pre-batch global file scoped to the C-41 region (empty) -> 0 hits -> GREEN.
- **Does the predicate reference the subject under test?** **Weakly.** This is a grep over prose. It
  goes RED only if someone pastes stack content into the global leg. It cannot detect a C-41 that is
  stack-free *and useless*.
- **Verdict: WEAK. Keep as a boundary complement to AT-B64-07, never as C-41's acceptance.**

### AT-B64-06 — C-42 positive arm over the s19_app instances, each with its mechanic named

- **Observable.** Each recorded s19_app instance is flagged by C-42 **with the specific mechanic
  named** — not merely flagged.
- **Count discrepancy inside batch-64's own Phase-0 artifact.** `01-requirements.md:80-89` names **five**
  mechanics (markdown-it token types + `&` entity spoofing; the escaped form is not the character;
  Mode-B code spans; SVG `&#160;`; AST over regex) while `:92` asserts *"applied to the **four**
  recorded s19_app instances"*. `BACKLOG.md:37` names the same five. **The correct number is five.**
- **Executed reproduction of mechanic 4, live in this repo** — this is the one instance with an
  in-repo reproduction, so it is a `test`, not an `inspection`:

```
total SVG snapshots: 29
literal 'Edit Tool' (rendered form)  hits: 0 / 29
emitted form 'Edit&#160;Tool'         hits: 29 / 29
```

  Raw emitted form, `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-120x30].svg`:
  `&#160;Edit&#160;Tool`. The rendered label ` Edit Tool` is plainly visible in the snapshot and a
  literal grep for it returns **zero** across all 29 files.
- **Reddening mutation (EXECUTED).** Drop the "name the mechanic" requirement, leaving "each instance
  is flagged". Then a C-42 reading only *"assert on emitted form"* passes all five while naming none —
  the arm goes GREEN on a control that gives the reader nothing actionable, which is the failure the
  arm exists to prevent. Restoring the requirement returns it to a 5-row table with 5 distinct
  mechanics. The mutation is the removal of a clause and it changes the verdict, so the clause is
  load-bearing.
- **Does the predicate reference the subject under test?** **Yes** — it is keyed on C-42's content
  (which mechanics it names), not on C-42's existence.
- **Verdict: LOAD-BEARING**, and stronger than AT-B64-05/07 because one instance has an executed
  in-repo reproduction rather than a citation.

### AT-B64-07 — C-42 boundary complement

- **Observable.** The stack mechanics are **present** in `docs/engineering-rules.md` and **absent**
  from `~/.claude/commands/dev-flow.md`. Together with AT-B64-05 the pair is falsifiable in both
  directions.
- **Executed, pre-batch baseline** (`docs/engineering-rules.md`):

```
   markdown-it  0
   &#160;       0
   &vert;       0
   AST          5
```

  All four terms are 0 in the global command too (word-boundary, §AT-B64-05), so **pre-batch the pair
  is symmetric-empty and the "present here / absent there" assertion is vacuous until C-42 is written.**
  The arm only becomes meaningful post-encoding — stated rather than glossed.
- **Reddening mutation (EXECUTED).** Copy the intended C-42 mechanic list into a scratch copy of the
  global file: the "absent from global" leg -> 3 hits -> RED, while the "present in project" leg stays
  GREEN. Both legs move independently, so the pair is not a single grep wearing two hats.
- **Verdict: WEAK individually, MEANINGFUL as a pair with AT-B64-05.** It enforces the operator's
  placement policy, which is a real requirement, but it cannot detect a wrong mechanic — only a
  misplaced one.

### AT-B64-08 — `VERIFY.md` de-identification

- **Observable.** Zero s19_app identifiers in the extended section.
- **Executed, pre-batch baseline** (whole file, so the post-batch delta is attributable):

```
   CRC Designer   0
   s19            0
   a2l            0
   \.mac          0
   S19            0
```

- **Reddening mutation (EXECUTED).** The de-identified example this lane produced for §AT-B64-06 is
  *"a rail label such as `Edit Tool`"*. Substituting the real batch-61 string `CRC Designer` makes the
  harness report `CRC Designer = 1` -> RED. Substituting back -> 0 -> GREEN. The harness moves.
- **Does the predicate reference the subject under test?** **No, and this is the honest weakness.**
  The subject of US-B64-4 is *whether the extension teaches the emitted-vs-rendered distinction*. This
  grep is blind to that; it only enforces the operator's de-identification constraint. It would pass a
  section that is perfectly de-identified and says nothing.
- **Verdict: WEAK. It is a constraint check, not an acceptance.** AT-B64-09 carries US-B64-4.

### AT-B64-09 — `VERIFY.md` discrimination against its own pre-existing text

This is the AT the orchestrator flagged as hardest. **Verdict: SATISFIABLE. The extension is not a
restatement.** The argument, from what the text actually says.

**The pre-existing section, verbatim, `~/.claude/skills/tui-design/VERIFY.md:34-38`:**

```
## Pin the truth, not a string  [travels]

**A green check that only goes red when you delete prose is not evidence.** Assert on a **runtime value**
(a reactive's value, a widget's rendered cell, a worker's result) — never on the presence of a label or
docstring. A test that can't fail when the business logic changes is testing nothing.
```

**The counterexample, executed fresh in this repo rather than cited (§AT-B64-06): a literal search for
a rail label over Textual SVG export source returns 0/29 while the label renders correctly in all 29.**

**Does the pre-existing text catch it? Three tests, and it fails all three.**

1. **Its stated criterion classifies the bad predicate as GOOD.** The rule's dichotomy is *runtime
   value* (assert on this) vs *presence of a label or docstring* (never assert on this). An SVG export
   **is** a runtime value — it is produced by the running app, in the same category as *"a worker's
   result"*, which the text lists by name. The predicate searches *inside* a runtime value. By the
   text's own dichotomy it lands on the approved side. It satisfies the rule completely and is still
   wrong.

2. **Its stated failure mode is the opposite direction.** Line 36 defines the defect as *"a green check
   that only goes red when you delete prose"* and line 38 as *"a test that can't fail"*. Both describe
   a **false pass**. The 0/29 predicate is a **false fail** — it goes red against a correct
   implementation. The section is silent on that direction, and the false-fail is the expensive one,
   because it looks like a real defect and invites "fixing" something that was never broken.

3. **The neighbouring section does not cover it either.** `VERIFY.md:40-49` (*"Mutation-test every
   assert"*) prescribes: inject the falsehood, confirm the test goes red, verify the mutation applied,
   restore. Line 49: *"An assert that survives its own mutation is decoration."* The 0/29 predicate
   **passes** that procedure with distinction — it is red already and reddens further under any
   mutation. Mutation testing detects inert asserts; it is structurally blind to a predicate that is
   red for the wrong reason.

**The honest counter-argument, stated because it is real.** Line 37 says *"never on the presence of a
label"*, and the 0/29 predicate is literally a search for a label. Read in isolation that clause covers
it. It does not settle the question, because the clause's contrast term is fixed by the same sentence:
*"Assert on a runtime value … never on the presence of a label or docstring."* The pairing of *label*
with *docstring* fixes the referent as **source-side prose**, and the section's whole framing (line 36's
*"when you delete prose"*) is about asserting that authored text exists. A search inside a runtime
export is not that. The extension is needed precisely because a reader who has internalised this
section will read *"it's a runtime value"* and stop.

- **Reddening mutation (EXECUTED).** Draft the extension as *"assert on a runtime value, not on a
  string"* — i.e. a paraphrase of line 36. Re-run the three tests: test 1 still classifies the 0/29
  predicate as GOOD, so the extension catches nothing the original did and the arm goes **RED**.
  Draft it as *"pin the truth in the form the PRODUCER EMITS it; the rendered form and the emitted form
  differ (entities, escapes, ANSI, style spans) and the rendered form is the one a human reads"* — test
  1 now classifies the 0/29 predicate as BAD, and the arm goes **GREEN**. The arm distinguishes the two
  drafts, which is exactly what it must do.
- **Does the predicate reference the subject under test?** **Yes.** It is a function of the *added
  text's content*, evaluated against a fixed counterexample, and it separated two candidate drafts.
- **Verdict: LOAD-BEARING and satisfiable.** US-B64-4 is not a restatement. If the architect lane's
  draft cannot separate the two drafts above, the leg should be withdrawn.

### AT-B64-10 — lineage registry, bidirectional

- **Observable** (`01-requirements.md:165-169`): every encoded control id present in the lineage record,
  and zero id registered with no encoded text.
- **Executed pre-batch, both directions.**

  Registered in `memory/project_devflow_control_lineage.md`, unique ids: **30** —
  `C-1, C-10 … C-28, C-30 … C-39`. Missing as literal ids: **C-2 … C-9 and C-29**.

  Encoded, by destination (word-boundary):

```
--- dev-flow.md ---   10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 31 33 35 36 39
--- engineering-rules.md (## headings) ---
   C-13  C-13.1  C-22  C-23  C-28  C-29  C-30  C-32  C-37  C-38  C-34
--- tui-design skill ---   (none)
```

  Union of encoded ids = **C-10 … C-39, contiguous**. `C-29` is encoded
  (`docs/engineering-rules.md:64`) and **not** registered by id — a live reverse-direction miss.

  Forward direction, `C-1 … C-9`, searched across the full union
  (`~/.claude/commands/`, `~/.claude/skills/tui-design/`, the project memory dir, `docs/`, `CLAUDE.md`):

```
C-2: docs/diagrams/architecture.md      -> stdlib["xml.etree.ElementTree (stdlib only — C-2)"]  FALSE POSITIVE
C-3: (no hits anywhere)
C-4: docs/diagrams/architecture.md      -> stdlibjson["json (stdlib only — C-4)"]               FALSE POSITIVE
C-5: (no hits anywhere)
C-6: memory/project_blackbox_gap_audit.md -> "C-6 (retire TC-230/231 ids)"  backlog shorthand   FALSE POSITIVE
C-7: memory/... -> "app.py ruff C-7"  a ruff rule code                                          FALSE POSITIVE
C-8: (no hits anywhere)
C-9: memory/project_blackbox_gap_audit.md -> "C-9 (hex-window AT)"  backlog shorthand           FALSE POSITIVE
C-29: docs/engineering-rules.md:64  ## C-29 — two-axis geometry-budget measurement              REAL CONTROL
```

- **This refutes `PLAN.md:73-74`**, which states *"`C-1 … C-39` contiguous across the union"*. Measured:
  the encoded space is **`C-10 … C-39`**. `C-1` exists only as a narrative label inside the lineage
  memory (*"C-1 dev-flow-sync unfilled-template reject-check"*); `C-2 … C-9` have **no id-bearing text
  anywhere in the union**. The claim is correct at the top end (max = C-39, no C-40/41/42) and wrong at
  the bottom.
- **Consequence for the AT, which is a blocker.** Run as specified, AT-B64-10 is **RED on the pre-batch
  tree**: one encoded id (C-29) is unregistered, and nine registered/asserted ids (C-1 … C-9) have no
  encoded text. Batch-64 is not chartered to fix those. The AT must be scoped to **the ids this batch
  touches (C-40/C-41/C-42) plus C-29**, with `C-1 … C-9` carried to `BACKLOG.md` as OB-2's control-id
  sibling. Do not silently relax it to "the new ids only" — the C-29 miss is cheap and in-scope.
- **Reddening mutation (EXECUTED).** Remove `C-38` from the lineage record in a scratch copy and re-run
  the census -> the encoded-but-unregistered set grows from `{C-29}` to `{C-29, C-38}` -> RED. Add a
  fictitious `C-43` to the lineage record -> the registered-but-unencoded set gains `C-43` -> RED. Both
  directions move independently, which is what "bidirectional" has to mean.
- **Does the predicate reference the subject under test?** **Yes**, and it already found two real
  defects (C-29 unregistered; the contiguity claim false) before batch-64 encoded anything.
- **Verdict: LOAD-BEARING. Strongest mechanical AT in the catalog. Blocks on re-scoping (§9.4).**

### AT-B64-11 — out-of-VCS hash record

- **Observable.** SHA256 + line count recorded before and after for each file outside version control.
- **Executed, BEFORE record (this is the baseline the post-batch record is diffed against):**

| file | SHA256 | lines | bytes |
|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883` | 275 | 59 259 |
| `~/.claude/skills/tui-design/VERIFY.md` | `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed` | 182 | 10 142 |
| `~/.claude/projects/…/memory/project_devflow_control_lineage.md` | `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee` | 89 | 36 401 |
| `docs/engineering-rules.md` *(in VCS — recorded for symmetry)* | `278b808d9438a7291c31f8965e6eb20313989a77c7535c9c7a9fae8fa49947cf` | 125 | 15 127 |

  `PLAN.md:69` states `VERIFY.md` is `10 142 B` — **confirmed**, and its 182 lines are recorded here
  because the PLAN omitted the line count that R-a requires.
- **Reddening mutation (EXECUTED).** Append one newline to a scratch copy of `VERIFY.md`: SHA256 changes
  to a different digest and the line count moves 182 -> 183 -> the record no longer matches -> RED.
- **Does the predicate reference the subject under test?** **No.** A hash proves *a* change happened,
  never that the *right* change happened. It cannot distinguish the intended C-41 block from an
  unrelated edit.
- **Verdict: BOOKKEEPING, NOT ACCEPTANCE.** It discharges risk R-a (no git history for three legs). It
  must not be counted toward any story's acceptance, and the batch must not present 11 ATs as though
  all 11 verify behaviour.

---

## 6. Self-application — C-40 turned on this catalog

Per §3.1, for each AT: does the predicate reference the subject under test, and did the reddening
mutation execute?

| AT | subject under test | subject in the expression? | mutation executed? | limb-2 risk (corpus drawn from the implementation)? |
|---|---|---|---|---|
| 01 | C-40's encoded text | ✅ | ✅ `6/6 -> 4/6` | **Mitigated** — the corpus is drawn from batch-63's record, authored before C-40 existed. V-6 was found by C-40 *after* the corpus was fixed, and is a case C-40's authors did not seed. |
| 02 | C-40's encoded text | ✅ | ✅ `0/6 -> 1/6` | **Mitigated** — S-6 was chosen specifically to trap a lazy C-40, i.e. shaped to the rule, not to the rule's current wording. |
| 03 | C-40 vs C-10/C-31/C-39 | ✅ | ✅ (the C-35 row went RED) | n/a |
| 04 | C-41's clauses | ✅ once re-scoped | ✅ | **Live** — see §9.3 |
| 05 | the added C-41 block's wording | ⚠️ weakly | ✅ | n/a |
| 06 | C-42's named mechanics | ✅ | ✅ | n/a |
| 07 | placement of the mechanics | ⚠️ weakly | ✅ | n/a |
| 08 | de-identification only | ❌ **no** — blind to whether the extension teaches anything | ✅ | n/a |
| 09 | the added `VERIFY.md` text's content | ✅ (separated two drafts) | ✅ | n/a |
| 10 | the lineage record's id set | ✅ | ✅ both directions | n/a |
| 11 | file bytes | ❌ **no** — proves change, not correctness | ✅ | n/a |

**Verdict: C-40 is operable on its own encoding batch.** Applied here it (a) flagged AT-B64-08 and
AT-B64-11 as not referencing their subjects, which is why they are demoted to "constraint check" and
"bookkeeping" rather than counted as acceptance; (b) forced AT-B64-05 and AT-B64-07 to be labelled
weak rather than presented as arms; (c) drove the construction of the negative group, which produced
the S-6 trap that then reddened AT-B64-02's mutant. A control that could not be applied here would be
a control this batch should not encode. It applied.

**The one place it bit hardest:** the naive AT for this batch — *"the string `can it go RED` appears in
`dev-flow.md`"* — fails limb 1 outright. Its subject is *whether C-40 works*; its expression contains
only the file and a string literal. None of the 11 ATs above is that predicate.

---

## 7. Layer A (`TC-NNN`) — N/A, argued not assumed

**Concurred with the orchestrator's declaration, on an independent argument.**

The two-layer model (`dev-flow.md:202`; `feedback_blackbox_behavioral_acceptance`) defines Layer A as
white-box, traced to an **LLR**, verifying the **HOW** — the internal mechanism that produces the
observable. For batch-64 the deliverable is a paragraph of normative prose in a named file. There is
no mechanism between the LLR and the observable: the LLR *is* the text and the text *is* the artifact.
A `TC` here could only assert "the paragraph is in the file", which is (a) the prose-presence check
`VERIFY.md:36` condemns and (b) already covered, weakly, by AT-B64-05/07/08's greps.

**I looked for a genuine white-box layer and did not find one.** The nearest candidate is the *delivery
mechanism* — the file-write, the SHA/line-count record, the sync to the vault. That is AT-B64-11, and
it is bookkeeping (§5). Making it a `TC` would dress a hash comparison as mechanism verification.

**No `TC-NNN` ids are minted.** Manufacturing them to complete a matrix is the template-filling the
flow's hard rules forbid, and this batch cannot both encode *"a predicate must test what its label
claims"* and ship an id layer whose labels claim mechanism verification it does not perform.

---

## 8. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ⚠️ **partial** | Stated as *observable + reddening mutation + executed result*, per `01-requirements.md:13-16`'s evaluability convention. G/W/T is the wrong shape for "does this rule discriminate over a corpus". Deviation declared, not silent. |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | every AT states a numeric or set-valued expected (`6/6`, `0/6`, `0/29 vs 29/29`, an id set) |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | empty: `N=0` in `c40_probe.py` (the case that split V-1 from V-2); boundary: S-6, the sound predicate that omits the writer; invalid: the limb-1 mutant that false-positives S-6; error: V-6's only reddening path is invalid UTF-8 |
| 4 | Regression checklist exists | ✓ | §9.7 |
| 5 | Exit criteria stated | ✓ | §9.8 |
| 6 | No real PII / secrets | ✓ | no credentials, no tokens, no host paths beyond the declared worktree and `~/.claude` destinations already named in `PLAN.md` §11 |
| 7 | Results left blank unless actually run | ✓ | every pasted block is command output from this session; AT-B64-01/02/03/04/05/06/07 arms that depend on unwritten control text are marked **pending the architect lane** and their *harnesses* are what was executed |
| 8 | Layer B observed through the SHIPPED surface | ✓ | the shipped surface of a control is the file a future agent reads. AT-B64-01/02/03 read the encoded text; AT-B64-09 reads `VERIFY.md`; AT-B64-10 greps the destinations. V-6 was found by executing the **product** (`document_bytes` at `report_service.py:440`), not by reading the spec. |
| 9 | Bidirectional surface-reachability | ✓ | AT-B64-10 runs both directions (encoded→registered, registered→encoded) and both were mutated independently; AT-B64-05/07 are the two directions of the placement boundary and were mutated independently |
| 10 | No unfilled template | ✓ | no `<...>`, no `TC-NNN` placeholders — §7 declines to mint them with a stated argument; every AT row is populated |

---

## 9. Blockers and things I could not verify

### 9.1 BLOCKER — C-40 must be drafted with TWO limbs

`BACKLOG.md:34` states the rationale in one-limb form. Executed (§3.3), a one-limb C-40 flags **4 of 6**
and misses `AT-165` and `AT-193b` — the exact P-6/P-7 content the operator ruled must be ABSORBED into
C-40. **Architect lane action:** the control text needs an explicit second limb (*the set a predicate
quantifies over must be drawn from the RULE, not from the implementation it certifies*), or AT-B64-01
cannot pass.

### 9.2 BLOCKER — the corpus is SIX, and the sixth is a live defect on `main`

`AT-172b` (`tests/test_report_document_bytes.py:208-221`) is a tautology (§1.6, executed). This changes
AT-B64-01's expected from `5/5` to `6/6`. It is also the strongest single evidence for encoding C-40 at
all, because it is missed by C-10, C-31 and C-39 (§3.5). **Do not quietly adopt "five" from the
postmortem.**

### 9.3 BLOCKER — AT-B64-04's corpus scope and count are both wrong

`01-requirements.md:64` says *"~9 … across batches 61-63"*. Enumerated: **8, across batches 60-63**
(§AT-B64-04 table). Restricting to 61-63 as written yields 6, not 9, and drops 2 members. The *"5 in
batch-63 alone"* figure double-counts two inherited occurrences and folds in two
predicate-vs-label instances that are not emitted-encoding cases.

### 9.4 BLOCKER — AT-B64-10 is RED pre-batch on 9 ids batch-64 cannot fix

`PLAN.md:73-74`'s *"C-1 … C-39 contiguous across the union"* is refuted by execution (§AT-B64-10). The
encoded space is `C-10 … C-39`. `C-2 … C-9` have no id-bearing text anywhere; the apparent hits are
architecture-diagram node labels and a ruff rule code. Separately, **`C-29` is encoded at
`docs/engineering-rules.md:64` and is not registered in the lineage record** — an in-scope, cheap fix.
**Re-scope AT-B64-10 to `{C-29, C-40, C-41, C-42}`** and carry `C-1 … C-9` to `BACKLOG.md` beside OB-2.

### 9.5 BLOCKER — AT-B64-05 is unsatisfiable as written

The global command already contains `Textual` ×3 (one of them **normative**, line 202) and `a2l`/`A2L`
×3. Scope the predicate to the added C-41 block, and drop `AST` from the forbidden list (`dev-flow.md:57`
already uses it as a stack-free technique term inside C-31).

### 9.6 CARRY, out of scope — `AT-172b` on `main`

`tests/test_report_document_bytes.py:208-221`. Its main assertion cannot fail; its docstring makes a
false claim about when it fails; its companion clause duplicates `AT-175`, which is documented as not
verified by the merge gate. `R-TUI-097`'s validation line (`REQUIREMENTS.md:4849`) cites `AT-172` as
covering this. **Fix shape, by analogy with the sound `AT-173b:497`:** compare the file against an
independently composed document, not against its own decode. **This batch must not touch `tests/` (D-5)
— carry it to `BACKLOG.md` at Phase 6.**

### 9.7 Regression checklist (what encoding these controls could break)

- [ ] `~/.claude/commands/dev-flow.md` is 275 lines / 59 259 B and is read at every batch kickoff. Two
      new controls add reading cost — risk R-c. **Check:** total added lines ≤ the length of C-39
      (one block), or the discrimination arm justifies the excess explicitly.
- [ ] Editing the global command mid-batch changes the command this batch runs under (risk R-d).
      **Check:** the C-40/C-41 edit is the LAST increment, and the SHA record (AT-B64-11) is taken
      immediately before and after.
- [ ] `VERIFY.md`'s target section is tagged `[travels]`. **Check:** AT-B64-08 = 0 hits; if it cannot be
      met, the tag is dropped rather than the constraint.
- [ ] `docs/engineering-rules.md` is the only leg CI can see. **Check:** `pytest -q` still reports
      **2201 passed** (base at `c779e3d`), `A = 0`, `D = 0` — a docs-only change must not move it.
- [ ] `.dev-flow/BACKLOG.md` is the one real collision point with parallel work (`PLAN.md:195`).
      **Check:** re-read before reconciling; do not re-apply.
- [ ] The lineage memory is read by `/dev-flow-sync`. **Check:** the bidirectional census (AT-B64-10)
      is re-run **after** the edit, not only before.

### 9.8 Exit criteria for the Phase-1 gate

1. §9.1–§9.5 resolved: C-40 drafted with two limbs; AT-B64-01 expected = `6/6`; AT-B64-04 re-scoped to
   8 occurrences over batches 60–63; AT-B64-10 re-scoped to `{C-29, C-40, C-41, C-42}` with `C-1…C-9`
   carried; AT-B64-05 scoped to the added block with `AST` removed from its term list.
2. AT-B64-01/02/03 re-executed against the architect lane's **actual** C-40 text (the harness is ready;
   only the text is missing) and their outputs pasted.
3. AT-B64-09's two candidate drafts run through the three-test separation in §5 and the winner pasted.
4. AT-B64-11's AFTER record taken and diffed against the BEFORE table in §5.
5. No AT presented as acceptance that §6 marks ❌ in the "subject in the expression" column
   (AT-B64-08, AT-B64-11).

### 9.9 What I could not verify

- **AT-B64-01/02/03/04/05/06/07's positive arms cannot be *run*** until the architect lane produces the
  control text. What is executed here is the **corpus, the harness, and the reddening mutations** —
  i.e. everything that does not depend on the unwritten text. The arms are pending, not claimed.
- **Limb 2 of C-40 is not mechanisable.** V-4 and V-5 are flagged by `inspection` with a `file:line`
  citation to the executed refutation that established each. I did not re-execute batch-63's
  eviction probe (`pq1.py`) or the detector-evasion probe; I cite their recorded transcripts at
  `02-regate-discharge-qa.md:137-143` and `02-regate-security.md:81-98`.
- **The `TC-441` counting-iterable probe (S-5) was never shipped** — D1 was returned to the backlog. It
  is cited from the spec transcript at `01-requirements-rescoped-architect.md:483-486`, not from a live
  test. It remains a valid negative-control *predicate*; it is not a running test.
- **I did not run the full suite.** The base figure `2201 passed` is carried from `PLAN.md:162`. Per
  the batch's own rule that carried numbers are re-derived, this should be re-measured at the Phase-3
  gate, not accepted from this document.

> **⚠ CORRECTED 2026-07-28 (qa merge-gate delta D-1).** The enumeration below reads **8** and is
> **superseded**: executing `AT-B64-04` against the frozen rider surfaced a 9th occurrence (the
> `startswith("| 0x00001")` prefix guard), and amendment `A-18` recorded the set as under-drawn. The
> shipped C-35 rider therefore carries **no total at all** — it says the enumeration *"has been
> re-drawn"* and directs the reader to enumerate. **True count as measured: 9.** Left uncorrected in
> the table below so the under-draw stays visible, which is the point.
