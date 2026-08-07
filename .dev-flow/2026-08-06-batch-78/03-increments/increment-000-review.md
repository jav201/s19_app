# Code Review — Increment 000 (batch-78 Inc-0, pre-change artifact capture)

> Independent reviewer. Did not author the code. Branch `claude/batch-78-cmdbar-a2bdiff`,
> range `601ea47..HEAD` (`6823352` capture + `8b77ea9` packet).
> Every claim in `increment-000.md` was treated as a self-report until re-executed.
> All mutations were run in a throwaway copy under the session scratchpad; the live tree
> was never modified (verified clean at close). No `git add -A`, no `git stash`.

---

## BLUF

**PASS — OK to advance.** No HIGH findings. One MEDIUM (a documented scope limit that is
narrower than the real gap) and two LOW.

The property that gives this increment its value — *the artifacts are a temporal freeze,
re-read from disk, that nothing in the test path can regenerate* — **holds under execution**.
The single strongest result: **the capture script pasted in §7, re-run independently by me in
a fresh process against a copy of the tree, reproduced all three artifacts byte-identically.**
That closes provenance (C-35), determinism (§4.6) and re-derivability in one shot.

| Severity | Count |
|---|---|
| HIGH | **0** |
| MEDIUM | **1** (F1) |
| LOW | **2** (F2, F3) |

---

## Scope reviewed

`git diff 601ea47..HEAD` — 6 files, +844/−0.

| File | Range |
|---|---|
| `tests/test_tui_commandbar.py` | `:566-936` (+370, new block only; nothing above `:566` touched) |
| `tests/goldens/batch78/at-b78-12-search-goto-payload.json` | new, 2 364 B |
| `tests/goldens/batch78/at-b78-03-palette-actions.json` | new, 778 B |
| `tests/goldens/batch78/at-b78-33-diff-hex-a-height.json` | new, 160 B |
| `.gitattributes` | `:17-24` (+8) |
| `.dev-flow/…/increment-000.md` | new (packet, commit `8b77ea9`) |

Read in full. Also read `01-requirements.md` §3 (LLR-121.1/.2/.3), §5.1 rules 1–10, §7 rows
Inc-0/Inc-1/Inc-10, `docs/engineering-rules.md`, `.gitignore`, `.gitattributes`.

---

## Verified sound (re-executed, not accepted)

### V1 — No production source changed ✅

I verified this **more strongly than the packet does**. The packet's check is
`git diff 601ea47..HEAD -- s19_app/` → empty (confirmed; and `s19_app/` is a real tree —
`s19_app/tui/app.py` exists — so the path check is not vacuous). But a path-scoped check
cannot prove the *absence* of changes elsewhere. The derived form:

```
git diff --name-only 601ea47..HEAD -- . ':(exclude).dev-flow' ':(exclude)tests'
→ .gitattributes          # only
```

`.gitattributes` is the sole non-test, non-devflow change; its added rule is scoped to
`tests/goldens/batch78/**`. Listed openly in packet §2. **Sound.**

### V2 — Byte fidelity of the *stored blob* ✅

Re-verified at all three layers, not just the working file:

| Artifact | `HEAD:` blob | index `:` | worktree | size | CR |
|---|---|---|---|---|---|
| `at-b78-03-palette-actions.json` | `65bfd6bf668a0249` | same | same | 778 | **0** |
| `at-b78-12-search-goto-payload.json` | `713be432b69cb2e0` | same | same | 2364 | **0** |
| `at-b78-33-diff-hex-a-height.json` | `167c7a4dd5ac5821` | same | same | 160 | **0** |

All three match `_B78_ARTIFACT_DIGESTS` exactly. `git check-attr text` → `unset` on all three
(the `-text` rule is in force and wins over `tests/goldens/** text eol=lf`, last-match-wins).
`core.autocrlf=true` confirmed on this host. **Sound.**

### V3 — Falsifiability of `TC-B78-44`, both limbs, independently reproduced ✅

This batch has had four mutations silently fail to apply, so each was **applied-verified before
running**, in a throwaway copy:

| Limb | Mutation (value recorded, not "a byte") | Applied? | Result |
|---|---|---|---|
| (a) | `"content_height": 7` → `8` in the stored artifact | verified `True`, 160→160 B | **RED** |
| (a) | reverted → digest back to `167c7a4dd5ac5821` | verified | **GREEN** |
| (b) | `_b78_artifact("x.json").write_text(...)` appended to `test_tui_directionb.py` | token count = 1 | **RED** |
| (b) | reverted | verified | **GREEN** |

Limb (a)'s mutated digest came out **`204594e3e7793e1d`** — **byte-identical to the value the
packet records at §4.4:172.** That is an independent reproduction of the author's evidence, not
a restatement of it.

### V4 — The C-40 co-assertions are load-bearing, not decorative ✅

The census's `assert swept` / `assert "test_tui_commandbar.py" in swept` could easily have been
vacuous. I neutered the sweep (`rglob` re-pointed at a non-existent subdirectory), applied-verified,
and the node **reddened**. The co-asserts bite.

### V5 — C-31: the census input set is derived, not hand-listed ✅

`sorted(Path(__file__).resolve().parent.rglob("*.py"))` → **153 modules**, including
`tests/conftest.py`. No hand-list. All test modules are flat in `tests/` (no subdirectories with
`.py`), so the `module.name` key used in `swept`/`offenders` has **zero basename collisions** today.
There is no repo-root `conftest.py` outside the sweep. **Sound.**

### V6 — C-35: captured from the shipped surface, and provably so ✅ *(strongest result)*

Judged by reading, then **proven by re-execution**. The capture drives shipped surfaces, not
builders in isolation:

- **payload** — `pilot.click("#search_button")` / `"#goto_button"` on the three screens' own
  shipped Buttons; a fresh `S19TuiApp` per row (correct — `last_search_address` is app-wide and
  would otherwise encode traversal order).
- **palette** — a real `pilot.press("ctrl+k")`, then `bar.visible_palette_actions()` (the widget's
  public accessor) with `palette_is_open` asserted first. **Explicitly not** `_build_palette_entries()`
  — which is the whole point, since `CommandBar(self._build_palette_entries())` is confirmed present
  at `s19_app/tui/app.py:1878`, exactly as BL-1 states.
- **geometry** — `action_show_screen("diff")`, then **both** layers recorded (C-32/C-37):
  `size.height` and the region intersected with `#screen_diff`.

Then the decisive check: I wrote the §7 script out **verbatim as pasted**, pointed it at a copy of
the tree, and ran it in a fresh process. Output:

```
at-b78-12-search-goto-payload.json 2364 713be432b69cb2e0
at-b78-03-palette-actions.json      778 65bfd6bf668a0249
at-b78-33-diff-hex-a-height.json    160 167c7a4dd5ac5821
```

**All three byte-identical to the committed blobs.** This simultaneously proves: the capture is
deterministic (§4.6 confirmed independently), the committed artifacts really came from that
shipped-surface path, and §7's script is complete enough to re-derive them.

### V7 — The artifacts corroborate the spec's own recorded baselines ✅

Independent cross-check against figures the spec recorded *before* this increment:

| Artifact | Observed | Spec's own recorded value | Match |
|---|---|---|---|
| geometry | `content_height 7`, `clipped_height 11` | §5.7 `AT-B78-33`: shipped **`(7,11)`** → compacted `(13,17)` | ✅ exact |
| palette | 37 ids, **37 distinct** | D-3 = 37; Phase-2 `PRE (True, 37, 37)` | ✅ exact |
| payload | 9 rows; `4102` / `4112`; miss+empty `None` | LLR-121.2 `→ (…,4102)/(…,4112)`, 9 rows | ✅ exact |

Three artifacts reproducing three independently-recorded figures is meaningful corroboration
that the right surface was driven at the right size.

### V8 — Field naming: `log_line_4_after_search` is accurate, not a phantom ✅

I flagged this as a suspected name/observation mismatch (the capture reads `log_lines[-1]`, "last",
while the field claims "line 4"). Checked the source: `s19_app/tui/app.py:1445` →
`self.log_lines = deque(maxlen=4)`. The deque holds **at most 4** lines, so `[-1]` *is* line 4 once
populated, and `[-1]` is the robust way to express it. **Not a finding.** The field name is the
spec's (LLR-121.2's declared row shape) and `_B78_ROW_KEYS` asserts all seven set-equal per row.

### V9 — Spec ids, naming convention, registry ✅

- `TC-B78-44` is **the spec's own id** (§3 boundary catalog `:272`; §5.5 `TC-06 → TC-B78-44`;
  §7 Inc-0). No id invented.
- Node name `test_tc_b78_44_pre_change_artifacts_are_frozen_on_disk` matches the **batch-77
  precedent exactly** (`test_tc_b77_10_…`, `test_tc_b77_11_…`). Convention-conformant (rule 11).
- `tests/test_id_registry.py` → **13 passed**. The new node does not orphan; G1–G7 green.

### V10 — Ledger ✅

- **377 collected** — I ran `--collect-only` over the nine gate files and got **exactly 377**,
  independently confirming the denominator of the author's `377 passed in 416.15s`. (The *pass*
  half I did not re-run — 7 min — but the count matching exactly is strong corroboration, and the
  suite form is stated: FULL, no marker filter, one run.)
- **D = 0, A = 1** — verified against the pinned base: `git show 601ea47:… | grep -c "^def test_"`
  → **13**; at HEAD → **14**. Arithmetic `2607 − 0 + 1 = 2608` is correct.
- The packet **states plainly** that 2608 is arithmetic and was not executed (§4.3, R-6). Correctly
  de-claimed under rule 8 / C-19. **Sound.**

### V11 — The three reported findings all hold

| Claim | Verdict | Evidence I produced |
|---|---|---|
| **F-1** `tests/_artifacts/` is gitignored | ✅ **TRUE** | `git check-ignore -v` → `.gitignore:14:tests/_artifacts/`. The substitute `tests/goldens/batch78/` **is** this repo's committed-golden convention — `tests/goldens/` already holds `batch35, 64, 71, 74, 76, 77`, and `.gitattributes:9` governs the tree. §7's Inc-0 row does name a path git refuses to track. |
| **F-2** three artifacts, not the brief's two | ✅ **TRUE and load-bearing** | The reasoning holds. §7 Inc-1 edits `styles.tcss`; §5.1 **rule 10** forbids an inline literal and §5.7 requires `AT-B78-33` compare against "the Inc-0 artifact's pre-change baseline, never an inline literal". The geometry artifact reproduces the spec's own `(7,11)`. **Following the two-artifact brief would have left Inc-1's gate with no legitimate oracle and no way to re-measure one.** Resolving in favour of the spec was correct. |
| **F-3** spec digest `0a159da97fa81714` is unreproducible | ✅ **TRUE** | I brute-forced **183 plausible serialisations** of the exact 9 rows (indent `None/0/1/2/4` × 4 separator forms × 3 line endings × 3 encodings, plus `repr`/`str` forms). **No match.** The spec pins sorted-key + `ensure_ascii` but leaves separators/indent/trailing-newline free — an unstated pattern is an unstated definition. |
| **F-3** the *new* digest is reproducible | ✅ **CONFIRMED** | `_b78_canonical_json(rows)` round-trips **byte-exactly** to the stored blob → `713be432b69cb2e0`. The recipe is now closed on both halves: serialisation pinned in `_b78_canonical_json` (`:673`, with its rationale) **and the fixture committed and named** in `_b78_loaded_s19` (`:686`) — which is precisely what the spec omitted. |

### V12 — The `-text` de-claim (F-4) is exactly right ✅

I built a throwaway git repo with `core.autocrlf=true` and committed the same bytes under each rule:

| File | `text eol=lf` blob | `-text` blob | Same? |
|---|---|---|---|
| the LF-only artifact | `e0dc96d3…` | `e0dc96d3…` | **identical** |
| a file carrying a CR | `422c2b7a…` | `4565b4dc…` | **divergent** |

**Confirmed, precisely as worded.** `-text` is correct but **not currently load-bearing** for these
three files, and it becomes load-bearing the moment an artifact carries a CR. The author neither
overstated the safety nor should the precaution be dismissed — keeping `-text` is right (it is the
batch-66/77 lesson, and `text eol=lf` is the *wrong* fix for evidence bytes), and saying so honestly
is the correct call. I would have raised this myself had it been claimed as active protection.

---

## Findings

### F1 — The census's documented scope limit is narrower than the real gap: it is verb-side, not only receiver-side  [Severity: **MEDIUM**]

- **What:** The docstring (`tests/test_tui_commandbar.py:850-853`) and packet R-2 state the only
  evasion is *"a module reconstructing the path from raw string literals"*. That is not the whole
  gap. I ran five regeneration forms against the node in a throwaway copy:

  | Probe | Form | Result |
  |---|---|---|
  | P1 | `(_B78_ARTIFACT_DIR / n).write_text(...)` | **RED** ✅ (caught — *better* than documented) |
  | P2 | `Path("tests/goldens/batch78/…").write_text(...)` | GREEN — **declared**, in scope |
  | P3 | `open(_B78_ARTIFACT_DIR / n, "w").write(...)` | **RED** ✅ |
  | **P4** | `shutil.copy(src, _B78_ARTIFACT_DIR / n)` | **GREEN — not declared** |
  | **P5** | `json.dump(rows, open(_B78_ARTIFACT_DIR / n, "w"))` | **GREEN — not declared** |

  P4 and P5 use the module's **own `_B78_ARTIFACT_DIR` symbol** — they do *not* reconstruct the path
  from raw literals — so they sit outside the stated limit while still evading. The gap is in
  `_B78_WRITE_METHODS` (the *verb* set, `:892`) and in only inspecting `node.func.value` (the
  receiver), never the arguments.

- **Where:** `tests/test_tui_commandbar.py:892` (`_B78_WRITE_METHODS`), `:918-923` (receiver-only
  check), `:850-853` (the scope-limit docstring); packet R-2.

- **Why it matters:** The node's own framing is *"it bounds accident, not intent."* **`json.dump(payload, open(path, "w"))` is the idiomatic way to write a JSON artifact** — it is the most likely
  *accidental* regeneration of these specific files, and it is missed. A future maintainer reading
  the stated limit would reasonably conclude the census covers it. Not HIGH because a real backstop
  exists: limb (a)'s digest assertion reddens if the bytes actually change, and a regenerated blob
  would show dirty in `git status`/CI. So this is a documentation-accuracy + coverage gap, not a
  false-confidence test.

- **Suggested fix** (small, keeps the C-31 derived sweep intact):

  ```python
  _B78_WRITE_METHODS = frozenset(
      {"write_text", "write_bytes", "write", "writelines", "mkdir", "touch", "unlink",
       "dump", "copy", "copyfile", "copy2", "replace", "rename"}      # + json/shutil/Path verbs
  )
  ...
      # match the artifact path in the RECEIVER *or* in any argument -- `json.dump(rows, open(p,"w"))`
      # and `shutil.copy(src, p)` name it only in an argument.
      segments = [node.func.value, *node.args, *(kw.value for kw in node.keywords)]
      blob = " ".join((ast.get_source_segment(source, s) or "") for s in segments)
      if "b78_artifact" in blob.lower():
          offenders.append(f"{module.name}:{node.lineno} {node.func.attr}")
  ```

  I confirmed both P4 and P5 name `_B78_ARTIFACT_DIR` in an argument, so this shape catches them.
  Either apply it here, or narrow the docstring to say the census keys on the *verb set* and list it.
  **Recommendation, not a blocker** — `software-dev` to apply if the operator wants it at Inc-0
  rather than carried to Inc-11 (where pending item 2 already revisits this node).

### F2 — §4.1's re-derivation command no longer reproduces its own recorded output  [Severity: **LOW**]

- **What:** Packet §4.1 records
  `git show HEAD~1:tests/test_tui_commandbar.py | grep -c "^def test_"` → **13**. At today's `HEAD`
  that command returns **14**, because committing the packet as `8b77ea9` shifted `HEAD~1` from the
  base `601ea47` to the capture commit `6823352`.
- **Where:** `.dev-flow/…/increment-000.md:128`.
- **Why it matters:** The **underlying claim is TRUE** — against the pinned base,
  `git show 601ea47:… | grep -c` → **13** and HEAD → **14**, so `D = 0, A = 1` is correct and the
  ledger stands. But a recorded figure whose stated command no longer reproduces it is exactly the
  re-derivability failure this batch keeps encountering (it is the same shape as F-3, one level down).
- **Suggested fix:** pin the SHA rather than a relative ref —
  `git show 601ea47:tests/test_tui_commandbar.py | grep -c "^def test_"  # -> 13`.

### F3 — File count: 5 in the code commit, 6 across the reviewed range  [Severity: **LOW**]

- **What:** `6823352` = **5 files** (at the cap, not over). `8b77ea9` = 1 more
  (`increment-000.md`). Range total **6**. §7's Inc-0 planned **3** *entries*; the expansion to 5
  paths is because `tests/_artifacts/…` was one entry covering three artifacts.
- **Where:** packet §2, `:81-83`.
- **Why it matters:** Nothing is hidden — the deviation is stated in §2 and the rationale (the
  packet is the mandated dev-flow deliverable, kept out of the capture commit so Inc-0 stays a pure
  pre-change freeze) is sound and is in fact the *right* call. Recording it so the operator rules on
  the counting convention rather than it becoming silent precedent.
- **Suggested fix:** none to the code. Fold into pending item 1 — amend §7 Inc-0 to name
  `tests/goldens/batch78/` and state the file count as 5.

---

## Notes for the other lanes (not my call)

- **`qa-reviewer`:** the `377 passed` *pass* result is the one executed figure I did not re-run
  (7 min). Collection count independently confirms 377. Also: pending item 5 (the owed second
  mutation on `_handle_goto`'s address parse, spec Q-m3) is a **coverage** question — the recorded
  `find_string_in_mem → lambda: None` pin reaches only the search half of the 9-row payload.
- **`security-reviewer`:** nothing found in my lane to hand over. No new data path, no network, no
  credential surface; the artifacts contain only fixture addresses (`4102`/`4112`) and shipped
  status strings. The one destructive command in the packet (`rm -f tests/goldens/batch78/*.json`)
  was on files the author had just created, immediately restored via `git checkout --` and re-hashed
  identical — I re-verified the current worktree bytes match the committed blobs.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Diff read in full | ✓ | 6 files, +844/−0; `tests/test_tui_commandbar.py:566-936`, `.gitattributes:17-24`, 3 artifacts, packet |
| Correctness pass (edge / None / error paths) | ✓ | `_b78_artifact` raises on missing (no producer fallback) `:681`; `getattr` without default fails loud `:766`; `log_lines` `deque(maxlen=4)` verified → V8; `content_height >= 1` guard `:900` prevents a 0-baseline making AT-B78-33's strict increase trivially satisfiable |
| Simplicity pass (no premature abstraction) | ✓ | Three single-purpose capture helpers, one reader, one node. No speculative generality. The write path is deliberately **outside** the repo — the right call, and the reason the freeze holds |
| Reuse / duplication checked | ✓ | Follows the batch-77 precedent it cites (`tests/goldens/batchNN/` + `-text`, `.gitattributes:10-16`); node naming matches `test_tc_b77_10_…`; no re-implementation of an existing util |
| Tests reviewed for intent, not behaviour | ✓ | Docstring states WHY (rule 10 / BL-1 / the 36==36 inertness), both limbs, and its own scope limit. Falsifiability re-executed on both limbs (V3) **and** on the C-40 co-asserts (V4) — none vacuous |
| Verdict explicit | ✓ | below |

---

## Verdict

- [x] **OK to advance**
- [ ] OK with the listed fixes applied first
- [ ] Block — must fix HIGH findings before advancing

**PASS.** No HIGH findings. The increment does what Inc-0 exists to do: it changes **no production
source**, it captures from the **shipped surface**, and the committed blob is **byte-identical to
what was captured** — each verified by my own execution rather than accepted from the packet. The
temporal freeze that breaks `AT-B78-03`'s `f(x) == f(x)` circularity is real and holds.

**F1 (MEDIUM) is a recommendation, not a gate.** It does not create false confidence in the frozen
bytes — the digest assertion backstops it — but the stated scope limit should be corrected either
way, since the batch's own recurring lesson is that a check's *label* must match what it tests.

Two things I want on the record as unusually good: the author **found and reported two spec defects
rather than absorbing them** (F-1's gitignored path, F-3's unreproducible digest), and **de-claimed
the `-text` attribute as not currently load-bearing when it would have been easy to bank it as a
safety win**. I tested that de-claim adversarially in both directions and it is exactly correct.
