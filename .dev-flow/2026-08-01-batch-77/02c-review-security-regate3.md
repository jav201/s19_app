# Security Re-Gate 3 — batch-77 revision 3 (Phase 2)

**Reviewer:** security lane · **Date:** 2026-08-01
**Subject:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` **revision 3** (645 lines) @ `9b1b744`
**Supersedes:** `02-review-security.md` (rev 1) · `02b-review-security-regate.md` (rev 2)
**Probes:** read-only, `PYTHONDONTWRITEBYTECODE=1` (C-46). No repo file modified.

---

## Verdict — CLEAN

**No blockers. No majors. Two minor gate-cell inconsistencies, neither of which needs a requirement change.**

All three of my prior findings are closed, and I verified each one by execution rather than by reading:

| Prior finding | Rev 3 disposition | Verified |
|---|---|---|
| **rev-1 B-1** — untrusted sink promoted to the load path with no acceptance | `LLR-116.6` + `AT-B77-15a/b`, painted-strip limb, non-frozen routing | ✅ |
| **rev-1 M-1** — vacuous collapse predicate + unbounded ruler | `LLR-112.2` rewritten against elision; ruler bounded | ✅ (closed at rev 2) |
| **rev-1 M-2** — missed `legend.py` prose site | site 7, owned by Inc-4 | ✅ (closed at rev 2) |
| **rev-1 m-1** — `text-style: reverse` hole | `LLR-117.2` strengthened | ✅ (closed at rev 2) |
| **rev-2 B-1r** — mis-verdicted + undischargeable ESC limb | **R-11** pulls the scrub in as `LLR-116.7`, Inc-2, before Inc-7 | ✅ **executed** |
| **rev-2 M-3r** — O(n²) merge loop on the UI thread | **R-10** removes aggregation to batch-78 with its measurements | ✅ **executed** |
| **rev-2 X-1** — my own false width-perturbation claim | withdrawn explicitly + recorded as P-57 | ✅ **swept** |

The batch's four new label surfaces remain free of file-derived text (rev-1 execution stands; R-10/R-11 add
no label sink). **No secret, credential, token, network call, dependency, external integration, destructive
command, auth flow or deploy surface** is touched. This is my third pass and I have nothing to block on.

---

## 1. The specified scrub works, and it does not damage symbol identity

`LLR-116.7` (`:455`) specifies: *"remove every C0 and C1 control byte … preserve every non-control
character verbatim, including square-bracket markup and URL-like substrings."* I implemented exactly that
(`[\x00-\x1f\x7f-\x9f]`) and probed the forms a naive `\x1b[...m` strip misses:

```
  author's reported case      -> 'sensor[31m_evil[red]'         match=True  residual_control=False
  bare ESC, no sequence       -> 'ab'                           match=True  residual_control=False
  CSI + parameter bytes       -> 'x[38;2;255;0;0mY[0m'          match=True  residual_control=False
  OSC-8 hyperlink, BEL        -> ']8;;http://evilclick]8;;'      match=True  residual_control=False
  OSC-8 hyperlink, ST         -> ']8;;http://evil\click]8;;\'    match=True  residual_control=False
  C1 single-byte CSI U+009B   -> 'a31mb'                        match=True  residual_control=False
  C1 single-byte OSC U+009D   -> 'a8;;ub'                        match=True  residual_control=False
  DEL U+007F                  -> 'ab'                           match=True  residual_control=False
  NUL + BEL + BS              -> 'abcd'                         match=True  residual_control=False
  newline / tab / CR          -> 'abcd'                         match=True  residual_control=False
  split across appends        -> '[31mred'                      match=True  residual_control=False
  ALL CLEAN: True
```

The author's reported case reproduces exactly. Three points worth recording:

- **The C1 forms are covered, and they are the ones a naive filter misses.** `U+009B` is single-byte CSI
  and `U+009D` single-byte OSC — functional equivalents of `ESC [` and `ESC ]` that carry no `\x1b`.
  A filter written as "strip `\x1b`-introduced sequences" would pass both. The specified **byte-class**
  filter catches them because it names the class, not the pattern. Correct choice.
- **`DEL` (U+007F) is caught** even though it is strictly neither C0 nor C1 — the specified range
  `\x7f-\x9f` includes it. Worth keeping; the wording *"C0 and C1"* is slightly narrower than the range,
  but the range is the safer one and the LLR's threshold examples pin the behaviour.
- **Escape *payloads* become visible text** (`\x1b[31m` → `[31m`). That is correct and safe: `Text()` does
  not parse markup, so a visible `[31m` is inert — confirmed by limb 2 below.

**It does not become the batch-62 redactor.** Zero damage across 14 legitimate identifier shapes:

```
  intact 'sensor_rpm' / 'ECU.Table[3]' / 'map[0][1]' / 'http://vendor.example/a?b=1&c=2'
  intact 'C:\proj\cal.a2l' / 'K\xfchlmittel_Temp' / '\u65e5\u672c\u8a9e' / 'a-b_c.d$e%f'
  intact 'x[link=file:///C:/W]click[/link]' / 'plain_ok' / '0x8000_BASE' / '\u0442\u0435\u0441\u0442'
  intact 'emoji_\U0001f600_name' / 'name\xa0with\xa0nbsp'
  legitimate names damaged: 0/14
```

URLs, Windows paths, bracket markup, non-ASCII identifiers, emoji and **NBSP (U+00A0, one codepoint above
the C1 range)** all survive byte-identical. This is a byte-class filter, not a shape-inference redactor —
structurally incapable of the batch-62 failure.

**One thing I checked because the filter lands in a shared symbol:** `safe_text` has **85 call sites across
4 modules** (`screens_directionb.py` 54, `app.py` 19, `issues_view.py` 6, `checks_view.py` 6), and it now
strips `\n`/`\t`. An AST census (not a line regex — C-42) over every `safe_text()` call in `s19_app/`:

```
  total safe_text() calls parsed: 80
  calls with a control char in a string literal argument: 0
```

**Zero.** No existing call site can lose developer formatting. `build_detail_text`'s newlines are appended
via `text.append(f"…\n")` (`:2378-2419`), never through `safe_text`, so they are untouched. The filter is
safe in this location.

---

## 2. `AT-B77-15a/b` is genuinely falsifiable on the ESC limb

This is the acceptance that closes my original finding, and the limb that was previously inert. Executed:

```
=== AT-B77-15a mutation: remove safe_text -> Text.from_markup ===
  post-Inc-2 (correct)   limb1=True  limb2=True   -> 15a GREEN
  MUTATED from_markup    limb1=False limb2=False  -> 15a RED

=== AT-B77-15b mutation: REVERT the filter (scrubbed -> raw) ===
  post-Inc-2 (correct)     limb3_noESC=True  -> 15b GREEN
  MUTATED filter reverted  limb3_noESC=False -> 15b RED
```

**The 15b mutation flips limb 3.** Revision 2's recorded mutation left it `False → False` — inert, which was
finding B-1r(c). Landing the scrub (R-11) is what created a substitutable value on that limb; the mutation
is now real. Six verdicts, precondition satisfied in every run:

```
  size=(80, 24)  limb1_payload=True  limb2_nospans=True  limb3_noESC=True
  size=(120, 30) limb1_payload=True  limb2_nospans=True  limb3_noESC=True
```

The three repairs I asked for are all present and correctly worded:
- **precondition stated in the AT body** (`:301-303`) — limb 3 evaluable only where limb 1 established the
  payload is present, not merely inherited from standing rule 3;
- **per-arm reporting** (`:304-305`) — 3 limbs × 2 sizes, and `LLR-116.6`'s threshold (`:454`) now spells the
  limb-3 lifecycle out loud: *"GREEN today VACUOUSLY (nothing rendered) … genuinely RED once Inc-7 lands
  auto-select, GREEN again once Inc-2's scrub lands"*;
- **split by dischargeability** (`:306-313`) — and the sequencing note at `:312` states the principle
  explicitly: *"It is never listed as a gate in a state where it cannot pass."*

**Inc-2 precedes Inc-7** (`:503-504`, ordering constraint 2), which is the structural fix — Inc-7 can no
longer introduce a gate the batch cannot satisfy. `C-77-h` is correctly marked **DISCHARGED by
implementation** rather than re-filed (`:99`).

---

## 3. My X-1 self-correction: withdrawn, and it does not survive anywhere

Swept the full document. **5 occurrences of the withdrawn claim, all inside explicit falsification framing:**

| Line | Context | Assertive? |
|---|---|---|
| `:35` | BLUF row 11 — *"withdrawn explicitly"* | ❌ no |
| `:106` | **P-57** — *"❌ FALSE — WITHDRAWN"* with my counter-evidence | ❌ no |
| `:277` | inside the ❌ WITHDRAWN block, quoting the false claim to negate it | ❌ no |
| `:281` | *"An attacker **cannot** perturb the bar through a symbol name"* | ❌ negation |

**Zero surviving assertions.** The withdrawal block (`:276-285`) carries my counter-evidence verbatim —
277→708 chars with ESC present, bar/grid/detail byte-identical at both regimes, `#map_detail` at
`width: 36` fixed — plus the point that matters most for batch-78: *"no file-derived string is an input to
`LLR-111.7` — the allocator consumes run byte-counts from `_merge_band_runs`, pure address arithmetic."*
P-57 records it in the premise table, so it is re-checkable from either end. **It will not reach batch-78 as
a premise.**

I note the document files this alongside P-38/P-44/P-45 as the same failure mode — *a plausible sentence
nobody had executed*. That is the right classification and it was my sentence.

---

## 4. C-27 dual guard — clean, and the cap pressure is relieved

```
  Inc-1: 4 files (      ok)  frozen=NONE      Inc-6: 4 files (      ok)  frozen=NONE
  Inc-2: 3 files (      ok)  frozen=NONE      Inc-7: 4 files (      ok)  frozen=NONE
  Inc-3: 3 files (      ok)  frozen=NONE      Inc-8: 4 files (      ok)  frozen=NONE
  Inc-4: 4 files (      ok)  frozen=NONE      Inc-9: 1 files (      ok)  frozen=NONE
  Inc-5: 5 files (      ok)  frozen=NONE

  frozen intersections: 0   increments over the 5-file cap: 0
```

Checked against the live `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-130`) and
`_ENGINE_TEST_FILES` (`tests/test_tui_directionb.py:5494-5504`). **The cap pressure I flagged at rev 2 is
resolved**: moving `tests/test_tui_hostile_map.py` into Inc-2 dropped Inc-7 from 5 files to 4, so landing
the scrub cost no headroom anywhere. `s19_app/tui/legend.py` and `safe_text` are both outside
`_ENGINE_PATHS` — verified, in scope.

---

## 5. Post-R-10 DoS — nothing quadratic remains, including out of domain

```
=== LLR-111.7 allocator, aggregation REMOVED (R-10) ===
  n=    14 bar= 66  in domain                   0.022 ms
  n=   801 bar= 66  OUT OF DOMAIN (avail<n)     0.001 ms
  n= 20000 bar= 66  OUT OF DOMAIN (avail<n)     0.003 ms

=== out-of-domain width computation (case_08 scale and beyond) ===
  n=    801  0.097 ms      n=   5000  0.650 ms
  n=  20000  2.730 ms      n= 100000  13.733 ms      <- LINEAR
```

**R-10 removed the only superlinear term in the batch.** The largest-remainder allocator is O(n log n) and
short-circuits out of domain in microseconds; the out-of-domain fallback is a single pass. At `case_08`
(801 ranges → 1601 segments) the new specified path costs **0.097 ms** of width arithmetic — the widget
mount of 1601 segments dominates, and that is pre-existing behaviour unchanged by batch-77, as the document
itself measures (`:172-181`: invisible-run count identical with and without the R-7 widen).

**Self-caught probe defect, recorded rather than reported.** My first out-of-domain measurement showed
801→2.4 ms, 5000→79 ms, 20000→1267 ms and looked quadratic. It was **my probe** recomputing `sum(rb)` inside
the comprehension, not the specified algorithm:

```
  n= 20000  sum-inside-loop 1199.283 ms (O(n^2), MY PROBE BUG)   sum-hoisted 2.364 ms (O(n))
```

Retracted before it became a finding. The specified computation is a single pass.

**The out-of-domain description is honest.** `:158-187` states plainly that on `case_08` the bar is
unreadable (99.5 % / 99.9 % of runs paint zero columns), that batch-77 does not fix it, and that it is not
made worse either. The two claims it *does* make normatively — no raise, all 801 regions reachable in the
region list — are the right two, and `AT-B77-18` covers them. **`C-77-l` charters batch-78 with the
measurements attached** (`:359`), so my M-3r did not evaporate: the onset formula, the six defects, and the
O(n²) finding all travel with it.

---

## 6. The census framing is honest and the derivation is sound

`LLR-112.3` (`:418-433`) now:
- lists my ninth site — `.dev-flow/2026-07-15-batch-47/06-docs/functionality.md:173` — and labels it
  *"a sibling of site 8 in the same folder, **missed twice**"*;
- replaces the integer with a **derived** threshold: *"**0** surviving statements … verified by **reading
  each file the sweep returns** rather than grepping for the id"*;
- states the limitation in the right direction: *"The integer was a LOWER BOUND in two consecutive
  revisions (6 → 8 → 9+), and **it will be wrong again**: prose restatements are invisible to an id-keyed
  grep **by construction**"*, with the batch-47 set's ~14 further restatements acknowledged;
- makes the **Statement** governing and the table illustrative — which is the correct precedence, since the
  Statement already says *"and the batch-47 artifact set"*;
- flags the `prototypes/` exclusion as deliberate.

That is sound. A derived threshold with a stated lower-bound caveat is the right shape for a predicate whose
subject is prose.

---

## Minor — two stale gate cells (no requirement change needed)

**m-4r — Inc-2's gate omits the C-34 full run, on the batch's widest-blast-radius edit.**
Inc-2 modifies `safe_text` (`:503`), used at **85 sites across 4 modules**. Its gate cell reads only
*"`AT-B77-15a` + `AT-B77-15b`, per limb per size; scrub-revert mutation executed"* — no `full ×3`, unlike
every other code increment. Standing rule 5 (C-34, `:412`) governs batch-wide and `tests/test_tui_directionb.py`
hosts TC-011/TC-030/the rail census, so this is a **cell inconsistency, not a hole**. Risk is low — my AST
census found 0 call sites that could lose formatting — but the increment with the widest reach should not
have the narrowest gate cell. **Recommend:** add `full ×3` to Inc-2's gate cell.

**m-5r — Inc-5's gate cell still says "8 sites reconciled".**
`LLR-112.3`'s threshold is now derived and its own table lists **9** (`:427`). The Inc-5 gate cell (`:507`)
was not updated with it. **Recommend:** replace with the derived wording so the gate matches its LLR.

---

## Evidence checklist

| Item | ✓ | Evidence |
|---|---|---|
| Findings carry what · where · why · recommendation | ✓ | m-4r, m-5r (no blocker/major to report) |
| Severity rated | ✓ | 0 blocker · 0 major · 2 minor |
| No secret values in output | ✓ | none in scope |
| Verdict explicit | ✓ | CLEAN — no blockers |
| New tool/integration scope + blast radius | ✓ | **N/A** — none added; `safe_text`'s 85-site blast radius measured instead (m-4r) |
| Scrub verified by execution incl. C1/OSC-8/DEL/split | ✓ | 11 forms, 0 residual control bytes |
| Scrub checked for identity damage | ✓ | 0/14 legitimate names damaged |
| Shared-symbol safety checked by AST, not regex | ✓ | 80 calls parsed, 0 control-char literals |
| ESC limb proven non-inert | ✓ | 15b mutation flips `True → False` |
| Six per-limb-per-size verdicts | ✓ | §2 |
| Withdrawn claim swept for residue | ✓ | 5 hits, all inside falsification framing |
| C-27 dual guard + file cap re-verified | ✓ | 0 intersections, 0 over cap |
| Post-R-10 complexity measured | ✓ | linear to n=100 000 |
| Own probe defect caught and retracted | ✓ | §5 |

---

## Bottom line

**Revision 3 is clean from the security lane. Proceed to Phase 3.**

R-11 fixed the right thing in the right place: the scrub is a **byte-class** filter (not a pattern matcher,
so C1 and OSC-8 forms cannot slip past), it lands in a **non-frozen** symbol, its acceptance is **genuinely
falsifiable** on the limb that was previously inert, and it is **sequenced before** the increment that makes
the clause live. R-10 removed the batch's only superlinear path and took its measurements with it.

The two minors are gate-cell text. Neither blocks Phase 3; fix them when convenient.

**No re-review needed from me.** If Phase 3 changes `LLR-116.7`'s filter from the specified byte-class form
to a pattern-based one, ping me — that substitution is exactly what would reopen the C1 and OSC-8 holes.
