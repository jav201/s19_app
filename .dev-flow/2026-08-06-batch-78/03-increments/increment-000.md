# Increment 000 — pre-change artifact capture

> **Scope:** §7 Inc-0 · LLR-121.2 · §5.1 rule 10 · **Node:** `TC-B78-44`
> **Enables:** `AT-B78-03` (Inc-10) · `AT-B78-12` (Inc-11) · `AT-B78-33` (Inc-1)
> Branch `claude/batch-78-cmdbar-a2bdiff` · base `601ea47` · **commit `6823352`** · artifact language: English.

---

## BLUF

**Three pre-change artifacts are committed, frozen, and provably unrebuildable — and executing
the increment turned up two places where the spec is wrong.**

| # | Finding | Verdict |
|---|---|---|
| **F-1** | **The spec's artifact path `tests/_artifacts/` is gitignored** (`.gitignore:14`). It is the *generated* pilot GIF/SVG output tree (`tests/test_examples_pilot_gifs.py:34`), and an artifact whose whole purpose is to be **committed** cannot live there. Artifacts placed in `tests/goldens/batch78/`, this repo's committed-golden convention (`.gitattributes:9`, batch-77 precedent). | ⚠️ **spec defect — worked around, reported not silently absorbed** |
| **F-2** | **My task brief named TWO artifacts; §7 Inc-0 names THREE.** The third — `#diff_hex_a.size.height` at 132×44 — is `AT-B78-33`'s only legitimate oracle (§5.1 rule 10 forbids an inline literal), and **Inc-1 edits `styles.tcss`, after which the pre-change value can never be re-measured.** Captured. | ⚠️ **brief/spec divergence — resolved in favour of the spec** |
| **F-3** | The spec's recorded digest `0a159da97fa81714` for the 9-row payload **is not reproducible**: LLR-121.2 states the recipe but never records the fixture the rows were captured against. Re-derived from a fixture that is now **committed in the test module**, digest `713be432b69cb2e0`. The *values* reproduce exactly (`4102` / `4112`, miss and empty rows `None`, 9 rows). | ✅ values reproduce; digest re-derived with cause |
| **F-4** | The `-text` attribute is **correct but not currently load-bearing** for these three files — the captured bytes are already LF-only, so `tests/goldens/** text eol=lf` would store the same blob today. It becomes load-bearing the moment an artifact carries a CR. Stated rather than overclaimed. | ✅ honest |

**No production source was touched:** `git diff 601ea47..6823352 -- s19_app/` is **empty**.

---

## 1. What changed

**Why this increment exists.** Phase 2 found `AT-B78-03` provably inert: the palette is built as
`CommandBar(self._build_palette_entries())` (`app.py:1878`), so a predicate comparing the observed
action set against `_build_palette_entries()` compares a producer with itself — it stayed GREEN at
`36 == 36` with an entire `Binding` removed. **What breaks the circularity is the temporal freeze,
not the capture path**, so this commit exists solely to create one, ahead of every production edit.

| Artifact | Content | Captured from | Consumer |
|---|---|---|---|
| `at-b78-12-search-goto-payload.json` | 9 rows — 3 screens × {hit, miss, empty}, LLR-121.2's seven declared fields | the three screens' **own shipped Buttons** via `pilot.click`, one fresh `S19TuiApp` per row | `AT-B78-12` (Inc-11) |
| `at-b78-03-palette-actions.json` | 37 action ids | `visible_palette_actions()` after a real `ctrl+k`, with `palette_is_open` asserted | `AT-B78-03` (Inc-10) |
| `at-b78-33-diff-hex-a-height.json` | `#diff_hex_a` at 132×44 — content `7`×`30`, clipped `11`×`34` | `action_show_screen("diff")`, both layers recorded (C-32/C-37) | `AT-B78-33` (Inc-1) |

**The capture code is shared; the write is not.** `tests/test_tui_commandbar.py` holds the fixture,
the matrix and the three `b78_capture_*` helpers, so the artifact and every later live capture run
*identical* code. The only thing that writes an artifact file is an **out-of-repo script** (§7 below,
pasted verbatim for re-derivability). `_b78_artifact(name)` reads and never falls back to a producer.

**`TC-B78-44` makes accidental regeneration a red test**, via an AST census over `tests/**/*.py` for
write-method calls whose receiver names `b78_artifact`, co-asserting the swept list is non-empty and
contains this module (C-40).

**Byte fidelity.** `.gitattributes` gains `tests/goldens/batch78/** -text` (batch-77 precedent:
evidence bytes are not normalised in *either* direction). `TC-B78-44` hashes `read_bytes()`, so a
lost attribute reddens here instead of drifting between a Windows checkout and Linux CI.

### The 9-row payload (executed)

```
{'screen': 'workspace', 'query': 'BOOT',         'goto': '0x1010',     'log_line_4_after_search': 'Found at 0x00001006',    'last_search_address': 4102, 'log_line_4_after_goto': 'Goto 0x00001010',                        'per_view_goto_focus_address': 4112}
{'screen': 'workspace', 'query': 'ZZZ_NO_MATCH', 'goto': '0xFFFFFFFF', 'log_line_4_after_search': 'Search text not found.', 'last_search_address': None, 'log_line_4_after_goto': 'Address 0xFFFFFFFF not in loaded file.', 'per_view_goto_focus_address': None}
{'screen': 'workspace', 'query': '',             'goto': '',           'log_line_4_after_search': 'Search text is empty.',  'last_search_address': None, 'log_line_4_after_goto': 'Goto address is empty.',                  'per_view_goto_focus_address': None}
{'screen': 'a2l',       'query': 'BOOT',         'goto': '0x1010',     'log_line_4_after_search': 'Found at 0x00001006',    'last_search_address': 4102, 'log_line_4_after_goto': 'Goto 0x00001010',                        'per_view_goto_focus_address': 4112}
{'screen': 'a2l',       'query': 'ZZZ_NO_MATCH', 'goto': '0xFFFFFFFF', 'log_line_4_after_search': 'Search text not found.', 'last_search_address': None, 'log_line_4_after_goto': 'Address 0xFFFFFFFF not in loaded file.', 'per_view_goto_focus_address': None}
{'screen': 'a2l',       'query': '',             'goto': '',           'log_line_4_after_search': 'Search text is empty.',  'last_search_address': None, 'log_line_4_after_goto': 'Goto address is empty.',                  'per_view_goto_focus_address': None}
{'screen': 'mac',       'query': 'BOOT',         'goto': '0x1010',     'log_line_4_after_search': 'Found at 0x00001006',    'last_search_address': 4102, 'log_line_4_after_goto': 'Goto 0x00001010',                        'per_view_goto_focus_address': 4112}
{'screen': 'mac',       'query': 'ZZZ_NO_MATCH', 'goto': '0xFFFFFFFF', 'log_line_4_after_search': 'Search text not found.', 'last_search_address': None, 'log_line_4_after_goto': 'Address 0xFFFFFFFF not in loaded file.', 'per_view_goto_focus_address': None}
{'screen': 'mac',       'query': '',             'goto': '',           'log_line_4_after_search': 'Search text is empty.',  'last_search_address': None, 'log_line_4_after_goto': 'Goto address is empty.',                  'per_view_goto_focus_address': None}
```

Reproduces the spec's stated baseline to the digit: `workspace q='BOOT' goto='0x1010' → (…,4102)/(…,4112)`,
miss and empty rows `None`, **9 payload rows**.

---

## 2. Files modified

| File | Status |
|---|---|
| `tests/test_tui_commandbar.py` | modified — **+370 / −0**, one new test node + capture/reader helpers |
| `tests/goldens/batch78/at-b78-12-search-goto-payload.json` | **new** — 2 364 bytes |
| `tests/goldens/batch78/at-b78-03-palette-actions.json` | **new** — 778 bytes |
| `tests/goldens/batch78/at-b78-33-diff-hex-a-height.json` | **new** — 160 bytes |
| `.gitattributes` | modified — one `-text` rule + its rationale comment |

**5 files — at the cap, not over it.** §7's "(3)" counts `tests/_artifacts/…` as one entry; the three
artifacts are three paths. This document is the mandated dev-flow deliverable and is committed
separately so the Inc-0 code commit stays a pure pre-change capture.

**Not touched:** `.dev-flow/state.json` (modified in the worktree by the parallel session — left
alone), `PLAN.md`, `00-measurements.md`, `01-requirements.md`, the `02-review-*.md` files,
`AT-TC-REGISTRY.jsonl`, `prototypes/memmap2.*`, and every file under `s19_app/`.

---

## 3. How to test

```bash
# the increment's own node
python -m pytest tests/test_tui_commandbar.py -q -p no:randomly

# gate set, ONE run (FULL form — no marker filter)
python -m pytest tests/test_tui_directionb.py tests/test_tui_commandbar.py \
    tests/test_tui_diff_screen.py tests/test_tui_variants.py \
    tests/test_tui_patch_variant.py tests/test_loadfilescreen_input.py \
    tests/test_id_registry.py tests/test_crc_designer_view.py \
    tests/test_universal_paste.py -q -p no:randomly

# the property that makes the artifacts a valid oracle
git diff 601ea47..6823352 -- s19_app/          # must be empty

# the stored blob, not the working file
git cat-file -s :tests/goldens/batch78/at-b78-12-search-goto-payload.json
git show :tests/goldens/batch78/at-b78-12-search-goto-payload.json | \
    python -c "import hashlib,sys; d=sys.stdin.buffer.read(); print(hashlib.blake2b(d,digest_size=8).hexdigest(), len(d), 'CR=',d.count(13))"

# checkout round-trip (the direction core.autocrlf corrupts)
rm -f tests/goldens/batch78/*.json && git checkout -- tests/goldens/batch78/
```

---

## 4. Test results

### 4.1 The increment's own file

```
$ python -m pytest tests/test_tui_commandbar.py -q -p no:randomly
..............                                                           [100%]
14 passed in 17.35s
```

**Node count, against PINNED SHAs.** The original evidence used `HEAD~1`, which drifted the moment
the packet commit landed (it recorded 13 and now returns 14). *A figure whose command drifts with
the commit graph is not re-derivable* — the same family as F-3's unstated fixture — so the base is
named explicitly:

```
$ git show 601ea47:tests/test_tui_commandbar.py | grep -c "^def test_"   # pinned base
13
$ git show 6823352:tests/test_tui_commandbar.py | grep -c "^def test_"   # Inc-0 capture
14
$ grep -c "^def test_" tests/test_tui_commandbar.py                      # working tree
14
```

**D = 0, A = 1.** The addendum commit adds no node — it rewrites `TC-B78-44`'s census in place.

### 4.2 Gate set — ONE run, FULL form (no marker filter)

```
$ python -m pytest tests/test_tui_directionb.py tests/test_tui_commandbar.py \
    tests/test_tui_diff_screen.py tests/test_tui_variants.py \
    tests/test_tui_patch_variant.py tests/test_loadfilescreen_input.py \
    tests/test_id_registry.py tests/test_crc_designer_view.py \
    tests/test_universal_paste.py -q -p no:randomly
........................................................................ [ 19%]
........................................................................ [ 38%]
........................................................................ [ 57%]
........................................................................ [ 76%]
........................................................................ [ 95%]
.................                                                        [100%]
377 passed in 416.15s (0:06:56)
```

C-34's full `tests/test_tui_directionb.py` is included even though Inc-0 touches none of the four
files that trigger it, because `test_id_registry.py` and `test_crc_designer_view.py` both run
repo-wide sweeps over `tests/` and this increment adds files there.

### 4.3 Ledger — **stated as arithmetic, not as an executed count**

| Quantity | Value | Form |
|---|---|---|
| baseline | `2607 passed / 2 skipped / 3 xfailed`, 29 snapshots, exit 0 | FULL, 25:57 |
| deleted (`D`) | **0** | — |
| added (`A`) | **1** (`test_tc_b78_44_pre_change_artifacts_are_frozen_on_disk`) | — |
| **post = 2607 − 0 + 1** | **`2608 passed / 2 skipped / 3 xfailed`** | **derived** |

⚠️ **The full suite was NOT executed for this increment** — per the task brief, the targeted files
were run instead (~26 min vs ~7 min). `2608` is arithmetic. The executed evidence is §4.2's
**377 passed / 0 failed** over the nine-file gate set, from one run's own output (C-19).

### 4.4 Falsifiability of `TC-B78-44` — both limbs, mutation **verified applied**, then reverted

**Limb (a) — byte fidelity.** Mutation: substitute the *value* `"content_height": 7` → `"content_height": 8`
in the stored artifact (recording the substituted value, not "corrupt a byte").

```
########## LIMB (a) MUTATION: flip one stored byte ##########
applied: content_height 7 -> 8; bytes 160 -> 160
E             - 167c7a4dd5ac5821
E             + 204594e3e7793e1d
tests\test_tui_commandbar.py:864: AssertionError
FAILED tests/test_tui_commandbar.py::test_tc_b78_44_pre_change_artifacts_are_frozen_on_disk
1 failed in 0.39s

########## LIMB (a) REVERTED ##########
1 passed in 1.06s
```

**Limb (b) — unrebuildability.** Mutation: append to `tests/test_tui_directionb.py` a function
calling `_b78_artifact('x.json').write_text('regenerated')`; presence of the token re-asserted
before running (the batch-78 lesson: *a mutation that does not mutate is a vacuous counterfactual*).

```
########## LIMB (b) MUTATION: a test module regenerates an artifact ##########
applied: _b78_artifact(...).write_text(...) added to tests/test_tui_directionb.py
E       AssertionError: a test module writes into the Inc-0 artifact path:
E       ['test_tui_directionb.py:8694 write_text']. The artifacts are a PRE-CHANGE freeze
E       ... assert not ['test_tui_directionb.py:8694 write_text']
tests\test_tui_commandbar.py:931: AssertionError
1 failed in 0.39s

########## LIMB (b) REVERTED ##########
1 passed in 1.07s
=== git status --short -- tests/ .gitattributes s19_app/ ===
(no tracked modifications = clean)
```

Both mutations were applied in the working tree, verified applied, reverted with
`git checkout -- <path>`, the predicate re-run **GREEN**, and `git status` re-checked clean.

### 4.4b ADDENDUM — limb (b) rebuilt to fail CLOSED (review F1), five forms executed

**The finding.** The first census hand-listed seven write verbs and inspected only the **receiver**.
The independent reviewer executed five regeneration forms against it and two came back **GREEN**:
`json.dump(rows, open(path, "w"))` and `shutil.copy(src, path)`. Both name this module's own symbol,
so the gap was **verb-side and argument-side**, inside the scope the docstring claimed to cover.

**Why this is the batch's signature defect one layer down.** A list of the verbs that *write* is a
**vacuous input set** — only as strong as a list someone remembered, and an omission leaves the
guard **green**. That is the same C-31 defect §6.4a's hand-filled propagation register had, and it
landed *inside the control built to prevent regeneration*. `json.dump` is *the* idiomatic way to
write JSON, i.e. exactly the accident being guarded against.

**The fix is the same one `enum.py` used: invert it so an omission fails CLOSED.** Not two names
appended.

| | before | after |
|---|---|---|
| match surface | receiver only | **the whole call — receiver OR any argument** |
| verb set | `_B78_WRITE_METHODS` — hand-listed **writes** | `_B78_NON_WRITING_CALLS` — allowlisted **non-writes**; everything else offends |
| an unanticipated verb | **GREEN** (silent hole) | **RED** (deliberate widening required) |
| aliasing | not handled | one level of **path-shaped** local aliasing, to a fixed point |

```
form                                     verdict
----------------------------------------------------------------------------------------------------
(unmodified tree)                        GREEN (census finds nothing)
A  path.write_text(...)                  RED   ['test_tui_directionb.py:8692 write_text()']
B  open(...).write(...)                  RED   ['test_tui_directionb.py:8692 write()', 'test_tui_directionb.py:8692 open()']
C  json.dump(rows, open(..., 'w'))       RED   ['test_tui_directionb.py:8692 dump()', 'test_tui_directionb.py:8692 open()']
D  shutil.copy(src, path)                RED   ['test_tui_directionb.py:8692 copy()']
E  alias then write (local aliasing)     RED   ['test_tui_directionb.py:8694 write_bytes()', 'test_tui_directionb.py:2783 sorted()', 'test_tui_directionb.py:2783 lower()', 'test_tui_directionb.py:2440 any()', 'test_tui_directionb.py:2443 any()']
----------------------------------------------------------------------------------------------------
(restored tree)                          GREEN (census finds nothing)
```

Each form was appended to a real test module, **the mutation re-asserted present before running**,
and the module restored with `git checkout --` plus a byte-equality check against the original.
**All four reviewer forms redden; form E (my own addition, local aliasing) also reddens.**

**Two things the rewrite cost, both stated rather than absorbed:**

1. **The census fired on its own allowlist declaration** — `frozenset({"_b78_artifact", …})`'s string
   literal names the reader. `frozenset` was added to the allowlist as a deliberate edit. This is the
   fail-closed design behaving correctly, and it is why the allowlist is documented member-by-member.
2. **Form E measured a real false positive.** Module-scoped taint bound the common name `p`, and the
   census additionally reported three unrelated calls (`sorted`/`lower`/`any`) elsewhere in that
   module. That is a false **positive** — a loud red test — never a false negative, and it only
   arises once someone introduces an artifact-path alias, which is exactly when loudness is wanted.
   **Per-function taint scoping would remove the noise and is deliberately not built:** ~25 lines of
   scope resolution inside a test guard buys accuracy the guard's purpose does not need. Recorded in
   the docstring as measured behaviour, so a future reader meets it as a documented property rather
   than as a bug. **Overrule this if you disagree — it is a judgement call, not a constraint.**

**Answer to the coordinator's question:** the verb set could not be *fully derived* — there is no
enumerable universe of "calls that write" the way `enum.py` has an enumerable corpus of grep terms.
So I inverted the polarity instead, which achieves the same property (an omission is loud, not
silent) without pretending to a derivation. The docstring now states the exact reach and the two
things outside it.

### 4.5 The staged blob, not the working file

```
$ git add … && for f in tests/goldens/batch78/*.json; do <hash worktree>; <hash git show :f>; done
tests/goldens/batch78/at-b78-03-palette-actions.json
  worktree blake2b8=65bfd6bf668a0249 size=778
  STAGED   blake2b8=65bfd6bf668a0249 size=778  CR bytes: 0
tests/goldens/batch78/at-b78-12-search-goto-payload.json
  worktree blake2b8=713be432b69cb2e0 size=2364
  STAGED   blake2b8=713be432b69cb2e0 size=2364  CR bytes: 0
tests/goldens/batch78/at-b78-33-diff-hex-a-height.json
  worktree blake2b8=167c7a4dd5ac5821 size=160
  STAGED   blake2b8=167c7a4dd5ac5821 size=160  CR bytes: 0

$ git check-attr text -- tests/goldens/batch78/at-b78-12-search-goto-payload.json \
                        tests/goldens/batch77/at-b77-02-gapless-band-strip.txt \
                        tests/__snapshots__/test_tui_snapshot/x.svg
tests/goldens/batch78/at-b78-12-search-goto-payload.json: text: unset
tests/goldens/batch77/at-b77-02-gapless-band-strip.txt: text: unset
tests/__snapshots__/test_tui_snapshot/x.svg: text: set
```

**Checkout round-trip** — the direction `core.autocrlf=true` corrupts (`git status` alone cannot
prove this; the files were deleted and restored through the smudge filter):

```
$ rm -f tests/goldens/batch78/*.json && git checkout -- tests/goldens/batch78/
at-b78-03-palette-actions.json      blake2b8=65bfd6bf668a0249  size=778   CR=0
at-b78-12-search-goto-payload.json  blake2b8=713be432b69cb2e0  size=2364  CR=0
at-b78-33-diff-hex-a-height.json    blake2b8=167c7a4dd5ac5821  size=160   CR=0
$ git status --short tests/goldens/
(clean)
```

### 4.6 Capture determinism

The capture was run **twice**, independently, in fresh processes. All three files hashed identically
(`sha256sum -c` → 3× `OK`). A non-deterministic capture would make every later live comparison a
coin-flip.

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| **R-1** | **The artifact path deviates from the spec** (`tests/goldens/batch78/` not `tests/_artifacts/`). Inc-1 / Inc-10 / Inc-11 must read the actual path. | medium | Forced by `.gitignore:14` (F-1). Recorded here and in the commit message; the paths are constants in `tests/test_tui_commandbar.py`. **Spec §7 should be amended.** |
| **R-2** | The AST census (limb b) is a **token census**. A module rebuilding the path from raw string literals, or passing it through a call's return value, still evades it. | low | Rebuilt to fail closed (§4.4b): whole-call matching + an allowlist of non-writing calls, so an unanticipated verb reddens. Reach and its two gaps stated exactly in the docstring. It bounds accident, not intent. |
| **R-2b** | Module-scoped taint **over-reports** when an artifact-path alias uses a common name — measured: `p` produced 3 unrelated hits in `test_tui_directionb.py` (§4.4b). | low — **fails closed** | A false positive is a red test, never a silent pass. Per-function scoping declined as over-engineering for a test guard; documented as measured behaviour. Reversible if the reviewer prefers it built. |
| **R-3** | The three captures use three different terminal sizes (160×40, 120×30, 132×44). A consumer driving a different size compares two layouts. | medium | The sizes are module constants (`_B78_CAPTURE_SIZE`, `_B78_PALETTE_SIZE`, `_B78_DIFF_SIZE`) and every consumer must import them. Called out in the module comment. |
| **R-4** | The digest assertion makes any legitimate re-capture a red test. | low — **by design** | That is the freeze. A re-capture after a production edit is precisely the defect being prevented. |
| **R-5** | `AT-B78-33` reads `content_height` from the geometry artifact; Inc-1 owns `tests/test_tui_diff_screen.py`, which does **not** import from `test_tui_commandbar.py`. | low | The artifact JSON is the contract; Inc-1 needs two lines of `json.loads(Path(...).read_text())`. Noted in §6. |
| **R-6** | Ledger post-count is arithmetic, not executed. | low | Stated explicitly in §4.3. |
| **R-7** | A parallel session is live in this worktree (`prototypes/memmap2.*`, `.dev-flow/state.json` modified). | low | Nothing outside my five files was staged, `git add -A` was never used, `git stash` was never used. |

**Security:** no new data path, no I/O outside `tests/`, no network, no credential surface, no
secrets in the artifacts (the payload holds only fixture-derived addresses and shipped status
strings). No dependency added.

---

## 6. Pending items

1. **Spec §7 Inc-0 should be amended** to name `tests/goldens/batch78/` and to state the file count
   as 5 (F-1). Not done here — I do not edit `01-requirements.md`.
2. **`TC-B78-44`'s limb (b) has no id of its own.** §7 Inc-0 allocates exactly one node and the
   no-regeneration census is arguably a second subject. Kept as one node with both clauses named in
   the docstring; split it at Inc-11 if the operator prefers one-subject-one-node strictly.
3. **The spec's digest `0a159da97fa81714` is unreproducible** and should be replaced by
   `713be432b69cb2e0` plus the now-committed fixture (F-3).
4. **Inc-1 must read the geometry artifact from disk**, not inline `7` (§5.1 rule 10). Two lines:
   `json.loads((Path(__file__).parent / "goldens" / "batch78" / "at-b78-33-diff-hex-a-height.json").read_text())["content_height"]`.
5. **Owed at Inc-11 (spec Q-m3):** a second mutation on `_handle_goto`'s address parse — the recorded
   `find_string_in_mem → lambda: None` mutation reaches only the search half of the payload.
6. **Open judgement call for the reviewer (§4.4b):** per-function taint scoping in the census —
   declined as over-engineering, measured false positive documented. Overrule if you disagree.

---

## 6b. Batch carry list — recorded, not re-litigated

Three items for the batch close. All three are **spec defects surfaced by executing the spec rather
than reading it**, which is this batch's own stated pattern (§10.2: *every blocker in three rounds
was in an acceptance or a control, never the measured foundation*).

| # | Item | Owner |
|---|---|---|
| **C-78-i** | **§7's Inc-0 row names a gitignored path.** `tests/_artifacts/` is ignored at `.gitignore:14` — it is the generated pilot GIF/SVG tree. §7 must be amended to `tests/goldens/batch78/` and to a file count of 5. | batch close |
| **C-78-ii** | **`LLR-121.2`'s digest recipe omits its fixture.** The recipe is stated; the memory it was captured against is not, so `0a159da97fa81714` is unreachable — the reviewer's 183-serialisation brute force confirmed it. Replace with `713be432b69cb2e0` and the now-committed `_b78_loaded_s19`. *An unstated fixture is an unstated definition* — the same lesson as the unstated grep pattern, recurring inside the recipe written to prevent it. | batch close |
| **C-78-iii** | **Coordinator brief/spec divergence, recorded at the coordinator's request.** The Inc-0 brief named **two** artifacts where §7 names **three**. Followed literally, Inc-1's `AT-B78-33` gate would have had no oracle **and no way to obtain one**, because Inc-1 edits `styles.tcss` and the pre-change 132×44 height cannot be re-measured afterwards. The spec was followed over the brief. **The general form: a brief that summarises a spec is a lossy copy, and the increment plan — not the brief — is the authority on what an increment must produce.** | batch close |

---

## 7. Suggested next task

**Inc-1 — HLR-125, compact the diff control rows** (`styles.tcss`, `tests/test_tui_diff_screen.py`).
Its gate `AT-B78-33` is now armed: `#diff_hex_a.size.height` at 132×44 must be **strictly greater**
than `7`, read from `tests/goldens/batch78/at-b78-33-diff-hex-a-height.json`, never inline. The
spec's executed expectation is 7 → 13.

### The capture script (out-of-repo, verbatim, for re-derivability)

Deliberately not committed: the write path must not exist inside `tests/`.

```python
"""batch-78 Inc-0 — capture the three pre-change artifacts."""
import sys, tempfile
from hashlib import blake2b
from pathlib import Path

REPO = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(REPO)); sys.path.insert(0, str(REPO / "tests"))
import test_tui_commandbar as T

OUT = REPO / "tests" / "goldens" / "batch78"
OUT.mkdir(parents=True, exist_ok=True)

def _write(name, payload):
    text = T._b78_canonical_json(payload)
    path = OUT / name
    with open(path, "w", encoding="utf-8", newline="") as fh:   # newline="" -> no translation
        fh.write(text)
    print(name, path.stat().st_size, blake2b(path.read_bytes(), digest_size=8).hexdigest())

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
    base = Path(td)
    _write(T._B78_PAYLOAD_ARTIFACT,     T.b78_capture_search_goto_payload(base))
    _write(T._B78_PALETTE_ARTIFACT,     T.b78_capture_palette_actions(base))
    _write(T._B78_DIFF_HEIGHT_ARTIFACT, T.b78_capture_diff_hex_a_geometry(base))
```

Run: `PYTHONDONTWRITEBYTECODE=1 python capture_inc0.py C:/Users/jjgh8/Github/s19_app`

**Independently reproduced.** The reviewer typed this script out verbatim as pasted, ran it in a
fresh process, and got all three artifacts **byte-identically** — which closes C-35 provenance,
determinism and re-derivability in one execution rather than three claims.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Tests / type checks / lint pass | ✓ | §4.2 — `377 passed in 416.15s`, one run, FULL form. **Re-run after the F1 census rewrite: `377 passed in 421.92s`, same nine files, one run.** Lint/type: repo runs neither in its gate suite. |
| No secrets in code or output | ✓ | Artifacts hold fixture addresses (`4102`, `4112`) and shipped status strings only; no env, no paths outside `tmp`. |
| No destructive commands without approval | ✓ | Only `rm -f tests/goldens/batch78/*.json` — files I created one minute earlier, immediately restored by `git checkout` and re-hashed identical (§4.5). No `git add -A`, no `git stash`, no force, no push. |
| File count within cap | ✓ | 5 tracked files (§2), cap is 5. Deviation from §7's "(3)" stated, not absorbed. |
| No production source changed | ✓ | `git diff 601ea47..6823352 -- s19_app/` → **empty** |
| Every node carries a spec id | ✓ | `TC-B78-44` — the only id §7 Inc-0 allocates. No id invented. |
| Node falsifiable, mutation applied-checked | ✓ | §4.4 — both limbs RED → reverted → GREEN, tree clean. **§4.4b — limb (b) rebuilt to fail closed; five forms RED, unmodified tree GREEN, each mutation re-asserted present and each restore byte-checked.** |
| Ledger evidence re-derivable | ✓ | §4.1 — commands pinned to `601ea47` / `6823352`, not `HEAD~1` (review F2) |
| Review packet attached | ✓ | this document, §§1–7 + §6b carry list |
