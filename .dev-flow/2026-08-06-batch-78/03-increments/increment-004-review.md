# Code Review — batch-78 Increment 4 (`HLR-123`)

**Reviewer:** `code-reviewer` (independent; did not author the change)
**Diff:** `24d812f..89d0a78` · **Branch:** `claude/batch-78-cmdbar-a2bdiff` · **Repo:** `C:\Users\jjgh8\Github\s19_app`
**Authority:** `01-requirements.md` §7 Inc-4 row · `HLR-123` · `LLR-123.1/.2/.3` · §5.3 `AT-B78-20…22` · §6.5 Amendment D · §8 `A-6`
**Method:** every figure below was re-executed in a detached worktree at `89d0a78`
(`scratchpad/wt78`, `git worktree add … --detach`). No file in the operator's tree was
modified. No `git add -A`, no `git stash`, no `git checkout` restore. `prototypes/memmap2.*`
(the parallel session's) untouched.

---

## BLUF

**The production code is correct and I could not break it. The block is on an evidence claim, not on the implementation.**

I reproduced every load-bearing figure in the packet, independently and from my own scripts.
The derivation is real, the four declared counterfactuals all redden on their own
assertions, and the three suites reproduce to the test. **Then I ran six mutations the
author did not run, and four of them left all ten Inc-4 nodes green.** One of those four is
the arithmetic the packet reports as **`A-6` DISCHARGED**.

| Severity | Count |
|---|:-:|
| **HIGH** | **1** |
| MEDIUM | 3 |
| LOW | 4 |

---

## Scope reviewed

| File | Lines | Read |
|---|---|---|
| `s19_app/tui/screens_directionb.py` | `+101 −14` — `on_list_view_highlighted` (`:7058-7088`), `_window_row_capacity` (`:7090-7118`), `_render_run_windows` (`:7120-7175`) | in full |
| `tests/test_tui_diff_screen.py` | `+652` — the Inc-4 block `:1928-2563` (3 ATs, 7 TCs, 4 helpers, 6 module constants) + `_diff_result`'s `paths=` at `:274-276, 311-314` | in full |
| `.dev-flow/2026-08-06-batch-78/01-requirements.md` | `+18 −1` — §3 `HLR-123` threshold (`:298`), §6.5 Amendment D (`:883-899`) | in full |
| `.dev-flow/2026-08-06-batch-78/enum.py` | `+9 −1` — `AT-B78-22 mutation` allowlist (`:68-76`) | in full, plus executed at both revisions |
| `.dev-flow/2026-08-06-batch-78/03-increments/increment-004.md` | `+301` (the packet under audit) | in full |

---

## What I verified as SOUND

### S-1 — the derivation is real, and a hard-coded number cannot pass

Re-measured from my own probe, six sizes, one fixture (`0x1000–0x1004`):

| terminal | `#diff_hex_a.size.height` | `#diff_hex_b.size.height` | equal | emitted hex rows | emitted lines |
|---|:-:|:-:|:-:|:-:|:-:|
| **132×44** | **13** | 13 | ✅ | **12** | 13 |
| **132×60** | **29** | 29 | ✅ | **28** | 29 |
| 132×24 | 0 | 0 | ✅ | 3 | 4 |
| 160×40 | 9 | 9 | ✅ | 8 | 9 |
| 120×30 | 0 | 0 | ✅ | 3 | 4 |
| 80×24 | 0 | 0 | ✅ | 3 | 4 |

The gate's discriminator holds: **132×44 → 12 and 132×60 → 28 at the same width.** Only
height moved and the count moved with it. The packet's `13 → 12` / `29 → 28` reproduce to
the digit. A hard-coded `40` fails twice over — the strict inequality (`40 < 40` false) and
`len(rows) <= content_h` (`40 <= 13` false). A width-derived count fails the strict
inequality. **`AT-B78-21` is not a single-height check and cannot be satisfied by a constant.**

### S-2 — all four declared counterfactuals redden, on their ASSERTION

Independent harness, per-node verdicts (CC-1), applied-check on every write, sha compared
against the **previous** mutation and the baseline. Baseline first: **10/10 PASSED**.

| Mutation | APPLIED | sha → | distinct from prev | nodes reddened | failure kind |
|---|:-:|---|:-:|---|---|
| **M1** `capacity = _window_row_capacity()` → `0` | ✅ | `5769dc32449de815` | ✅ | `AT-B78-21`, `TC-B78-45`, `TC-B78-24` | `AssertionError` ×3 |
| **M2** `high = end + ctx` → `high = end` | ✅ | `68941fa401e97fcf` | ✅ | **`AT-B78-22`**, `TC-B78-24`, `TC-B78-25`, `TC-B78-28` | `AssertionError` ×4 |
| **M3** selection wire → `_render_run_windows(0)` | ✅ | `61463c55db23c79b` | ✅ | **`AT-B78-20`**, `TC-B78-28` | `AssertionError` ×2 |
| **M4** header kind label → `f""` | ✅ | `6164dea60ea04cf3` | ✅ | **`AT-B78-20`** | `AssertionError` ×1 |

`FINAL sha=2429d588ed343e44 == baseline`. **Zero `TypeError`, zero `ImportError`, zero
collection errors, in any arm.** Every reddening carries the node's own message, e.g. M2:

```
E   AssertionError: the window must span exactly the run plus one context row on each
    side; expected ['0x00000FF0','0x00001000','0x00001010'], emitted ['0x00000FF0','0x00001000']
```

**§7's Inc-4 requirement — *"`AT-B78-22` reddens on its ASSERTION under `high = end + ctx →
high = end`"* — is satisfied and independently reproduced.** The `C-78-xv` defect that cost
Inc-3 its `LLR-122.4` discharge did not recur. The applied-check found no silent no-op:
every `old` token was present before the write and absent after it, and every sha differs
from its predecessor.

Two of the mutations redden *more* nodes than the packet reports; the author ran one node
per mutation, I ran all ten. Broader, same conclusion.

### S-3 — `on_list_view_highlighted` displaces nothing

- `app.py:7477` belongs to **`S19TuiApp`** (`class` at `:1318`); `screens.py:1981` belongs to
  **`OperationsScreen(ModalScreen[None])`** (`class` at `:1845`) — a modal screen, not an
  ancestor of `AbDiffPanel` (`class` at `:6568`).
- `AbDiffPanel.compose` yields exactly **one** `ListView` (`#diff_range_list`); there is no
  sibling list inside the panel whose highlights this handler could swallow.
- The new handler does **not** call `event.stop()`, so bubbling to the Screen and App is
  intact. Confirmed empirically: the full `tests/test_tui_directionb.py` guard host passes
  unchanged (§S-6).
- The `item.id.startswith("diff_run_")` guard is correct: `_run_note_item` mints its rows
  with **no id at all**, so the three context rows and the cap notice can never be parsed
  as a run index, and `item is None` (mid-rebuild) returns first.

⚠️ The packet's *reason* for this is backwards — see **F-6**. The *conclusion* is right.

### S-4 — `_window_row_capacity`: `min` and `−1` both judged and both verified

**The `−1` is load-bearing.** Mutating `min(heights) - 1` → `min(heights) - 0` reddens
`AT-B78-21` and `TC-B78-24`. Without it the widget emits `height + 1` lines into `height`
rows and the last hex row clips away silently — the exact C-32 layer confusion. The
`lines_a <= content_h` clause in `AT-B78-21` is what catches it, and it is the clause that
distinguishes this from a `rows <= height` test that would pass a clipped window.

**The `min` rationale is accepted, and it is stronger than the packet argues.** The stated
premise — *"the two are siblings under one `1fr` row and measure equal"* — is true for
**height** at all six sizes I measured, but is **already false for width at 80×24**
(`#diff_hex_a` 18 cells, `#diff_hex_b` 19). So the two panes are not guaranteed symmetric
even today, on one axis. That makes `min` an honest bound rather than speculative
generality, and I would keep it. It is currently **unobservable** (`min(heights)` →
`heights[0]` leaves 10/10 green) — declared by the author as `R-4`, correctly.

The stated rationale itself — *a diff is unreadable if the two columns disagree on
line-to-address mapping* — is right, and it is enforced positively: **four separate nodes**
assert `rows_a == rows_b` (`AT-B78-20`, `AT-B78-21` per size, `AT-B78-22`, `TC-B78-26`).

### S-5 — one-directional growth and the address-0 clamp

Executed at address 0 (`0x0000–0x0004`) at **132×44**: the window starts at
**`0x00000000`** and still emits **12** rows into a 13-row pane. The rows the clamp refuses
above the run are recovered below, exactly as claimed — the count stays `capacity` because
`rows = capacity` is assigned *after* the clamp, so `low` moving is decoupled from the
length. The naive form the packet names (*subtract, clamp, generate to the old `high`*)
emits 2 rows here, and `TC-B78-24`'s `len(rows) == content_h - 1` catches it.

The one-directional guard is load-bearing: mutating `if capacity > rows:` →
`if capacity >= 0:` (which also lets the pane *shrink* the mandatory span) reddens five
nodes — `AT-B78-22`, `TC-B78-24`, `TC-B78-25`, `TC-B78-26`, `TC-B78-28`.

### S-6 — the three suites reproduce, and the ledger arithmetic holds

Re-executed in the worktree, one run each, full form:

| Suite | Packet | Re-executed | Match |
|---|---|---|:-:|
| `tests/test_tui_directionb.py` (C-34 guard host, full file per `docs/engineering-rules.md:190`) | 183 passed | **183 passed in 180.30s** | ✅ |
| `tests/test_tui_diff_screen.py` + `tests/test_tui_diff_compare_realpath.py` | 40 passed | **40 passed in 60.43s** | ✅ |
| `tests/test_tui_snapshot.py` | 1 failed / 31 passed, drift = `[diff-comfortable-120x30]` | **1 failed, 31 passed in 56.45s**; the sole failure is `test_tc016s_density_layout_snapshot[diff-comfortable-120x30]` | ✅ |

**Node census:** `tests/test_tui_diff_screen.py` collects **34** at `89d0a78` against **24**
at `24d812f` — `+10`, `D = 0`. `2626 + 10 = 2636` is sound as arithmetic, and the packet
states it as arithmetic rather than as a suite read. Honest.

**Snapshot drift, checked structurally rather than by argument:** there is exactly **one**
diff golden in the whole tree (`test_tc016s_density_layout_snapshot[diff-comfortable-120x30].svg`),
and **zero** goldens contain the string `Image A`. The header's new kind label therefore
*cannot* move a second cell — the packet's P-33b reasoning is right, and the structural
fact is stronger than the reasoning it gives.

### S-7 — the panel stays presentational; G-9 caps unchanged

No line of the source diff mentions `report`, `write`, `_apply_display_caps` or a `runs=`
kwarg (grepped over the `+`/`−` lines). `_render_run_windows` reads `self._runs` (the
capped list) and `self._mem_map_a/b` only. The G-9 caps still bound what the panel paints,
never what the report writes; Inc-3's `AT-B78-31` is untouched and green in the 40-node run.

### S-8 — C-17, C-26, and the `_KIND_LABEL` citation

- **C-17 holds.** `#diff_hex_a` / `#diff_hex_b` are still constructed `markup=False`. The
  new header composes an `int`, two `int`s formatted `:08X`, and a value from a
  module-constant dict — no file-derived text reaches it. (⚠️ the packet's line citation for
  this is stale — **F-5**.)
- **C-26 reverse-grep, whole `tests/` tree.** All ten new module-level symbols
  (`_B78_INC4_TALL/_WIDE/_SHORT`, `_B78_AT22_RUN`, `_B78_AT22_ADDRESSES`, `_B78_HEX_ROW`,
  `_b78_window_text`, `_b78_window_rows`, `_b78_window_geometry`, `_b78_select_run`) resolve
  to **`tests/test_tui_diff_screen.py` only**. No consumer outside the owning module. ✅
- **F-3 is correct.** `_KIND_LABEL` is at **`:6639-6643`** on this branch; §4's `:6637-6641`
  is stale by two lines. Content re-derived: three entries,
  `{"changed": "changed", "only_a": "only A", "only_b": "only B"}`.

### S-9 — `TC-B78-27`'s premise is sound by construction, not by luck

`render_comparison` assigns `self._runs = capped` **before** awaiting `_render_run_list`,
so no `Highlighted` event emitted during the rebuild can ever see a stale `_runs`. The
bounds guard in `_render_run_windows` is a second line of defence rather than the only one.
Good ordering; worth keeping the comment that says so.

### S-10 — `C-78-xix` (the re-derivability lesson) reproduces

§3 records `(132,60) → pane h=23` and `132×44 → 7`. I measure **29** and **13** on this
branch. `29 − 6 = 23` and `13 − 6 = 7`; BL-2 publishes Inc-1's `+6`. **Both figures
reproduce once the increment is stated and neither reproduces as a bare number.** The
lesson is well-founded and I would encode it. (⚠️ its *id* collides — **F-3 below**.)

---

## Findings

### F-1 — `A-6` is reported DISCHARGED, but the centring arithmetic is pinned by nothing  ·  **[HIGH]**

- **What.** The packet's F-2 declares **`A-6` DISCHARGED**, §6 item 3 says *"`A-6` is
  discharged (§8 can be marked)"*, and §1.3 states the shipped behaviour as
  *"Half the surplus above, the remainder below"*. **No predicate in the increment can
  fail when that arithmetic changes.** I ran both directions:

  | Reviewer mutation | Substitution | Inc-4 nodes reddened |
  |---|---|:-:|
  | **R5** — all surplus ABOVE | `low - ((capacity - rows) // 2) * HEX_WIDTH` → `low - (capacity - rows) * HEX_WIDTH` | **0 of 10** |
  | **R6** — all surplus BELOW | `low - ((capacity - rows) // 2) * HEX_WIDTH` → `low - 0 * HEX_WIDTH` | **0 of 10** |

  Both APPLIED-checked, both sha-distinct, tree restored (`FINAL sha == baseline`).

- **Where.** `s19_app/tui/screens_directionb.py:7165` (the centring line) ·
  `increment-004.md:20` (F-2, "A-6 DISCHARGED") · `increment-004.md:259` · `01-requirements.md:994` (§8 `A-6`).
- **Why it matters.** `TC-B78-24`'s `len(rows) == content_h - 1` pins the **count**, which
  R5 and R6 both preserve — it pins nothing about the **position**. So the one behaviour
  `A-6` names is the one behaviour with no discriminating test, and marking `A-6` discharged
  in §8 is a durable state change that removes it from future scrutiny. In this batch's own
  vocabulary (`C-78-xv`, *a control, not a wish*), a measurement recorded in prose is a wish.
  This is the project's dominant defect class — the vacuous acceptance — sitting in a spec
  disposition rather than in code, which is exactly where this batch's other thirteen
  defects have been.
- **Note the scope carefully:** the shipped arithmetic is **correct**. I measured it: at
  132×60 the run row sits at index **13 of 28** (13 above / 14 below). The defect is the
  *discharge*, not the implementation.
- **Suggested fix — one assertion, no new fixture, no new driver.** Add a third read to
  `test_at_b78_22_window_spans_the_run_plus_context` (or a fourth arm in `TC-B78-24`) at a
  size where the clamp does not bind:

  ```python
  # A-6: the surplus rows are split EVENLY around the run. A count assertion
  # cannot see this - `all above` and `all below` both keep the count.
  tall = _b78_drive_compare(tmp_path, _B78_INC4_TALL, _diff_result([_B78_AT22_RUN]), after=_after)
  run_row = _B78_AT22_RUN[0] - (_B78_AT22_RUN[0] % 16)
  above = tall["rows_a"].index(run_row)
  below = len(tall["rows_a"]) - above - 1
  assert abs(above - below) <= 1, (
      f"the surplus rows must be split evenly around the selected run (A-6); "
      f"emitted {above} rows above it and {below} below, of "
      f"{len(tall['rows_a'])} into a pane of {tall['content_h']}"
  )
  ```

  **Executed against all three trees** (probe run in the worktree, restored):

  | tree | first row | above | below | `abs(above−below)` | verdict |
  |---|---|:-:|:-:|:-:|:-:|
  | baseline `89d0a78` | `0x00000F30` | 13 | 14 | **1** | ✅ passes |
  | R5 (all above) | `0x00000E60` | 26 | 1 | **25** | 🔴 reddens |
  | R6 (all below) | `0x00000FF0` | 1 | 26 | **25** | 🔴 reddens |

  It asserts a *property* (evenness), not an absolute index, so US-78-1's `+3` rows will not
  move it — which is what §3's C-29 warning asks for.
- **Until it is added,** `A-6` must not be marked discharged in §8.

### F-2 — `LLR-123.3`'s threshold is not discharged: the label MAPPING is untested  ·  **[MEDIUM]**

- **What.** `LLR-123.3`'s numeric pass threshold reads *"the header contains the kind label
  for **a run of each of the three kinds**"*. Only one kind is asserted anywhere, and it is
  the one kind for which the mapping is the identity: `_KIND_LABEL["changed"] == "changed"`.
  Reviewer mutation **R7**, `self._KIND_LABEL.get(kind, kind)` → `kind` (**2 occurrences** —
  the header at `:7172` *and* the run-list label at `:7011`) leaves **0 of 10** nodes red.
- **Where.** `tests/test_tui_diff_screen.py:2102-2105` (`assert "changed" in header`) ·
  `s19_app/tui/screens_directionb.py:7172` and `:7011` (the two `.get(kind, kind)` sites) ·
  `01-requirements.md:536`.
- **Why it matters.** M4 (deleting the segment entirely) does redden, so the gate is not
  vacuous — but the specific clause the spec's threshold names is unverified, and the
  regression it fails to catch is user-visible: the header would read `only_a` instead of
  `only A`. This is `C-40`'s shape applied to the *content* of a field rather than its
  presence.
- **Suggested fix.** `AT-B78-20` already captures run 0, whose kind is `only_a`. One line on
  the `before` capture, no new driver, no new fixture:

  ```python
  assert "only A" in before["header_a"] and "only_a" not in before["header_a"], (
      f"the header must name the run's LABEL, not the raw kind key (LLR-123.3); "
      f"header={before['header_a']!r}"
  )
  ```

  Passes today — M3's own failure output shows run 0's header as
  `Image A — Run #0 0x00000000-0x00000004 only A` — and reddens under R7.

### F-3 — carry-id collision: `C-78-xviii` names two different lessons  ·  **[MEDIUM]**

- **What.** Two files committed in this increment assign the same id to different carries:

  | Location | `C-78-xviii` is… |
  |---|---|
  | `01-requirements.md:898` (Amendment D) | *"a measured figure is re-derivable only with the INCREMENT it was measured at"* |
  | `increment-004.md:268` (§6b) | *"a requirement with two exactness clauses owes the region where they are jointly satisfiable"* |

  `increment-004.md:269` then gives the first lesson `C-78-xix`. The requirements file's
  cross-reference *"(Inc-4 F-2)"* is also wrong — the packet's F-2 is `A-6`, not the figures.
- **Where.** `01-requirements.md:898` · `increment-004.md:268-269`.
- **Why it matters.** Under this project's enforced carry-over reconciliation, a duplicate id
  means one of the two lessons is silently dropped or mis-attributed at batch close. Both
  lessons are good; losing either would be a real cost.
- **Suggested fix.** In `01-requirements.md:898`, renumber to **`C-78-xix`** and change the
  pointer to *"(Inc-4, the BLUF figures note)"*. Or drop the id from §6.5 entirely and
  reference the packet's §6b as the single owner — the increment packet is the natural home
  for a carry, and the requirements file is quoting it.

### F-4 — the propagation gate's verdict was discarded by a pipe  ·  **[MEDIUM, process]**

- **What.** Reproduced exactly. `enum.py` at `75c9714`, run against `01-requirements.md` at
  `75c9714`, exits **1**:

  ```
  AT-B78-22 mutation   4 hit(s)  §3,6.5,6.4a,7   UNDISPOSITIONED -> [(894, '6.5')]
      UNDISPOSITIONED  line 894  §6.5: **Why this is an amendment and not a test relaxation** …
  GATE: FAIL — 1 term(s) with a stale form or an undispositioned hit
  EXIT_OF_GATE=1
  ```

  The gate ran, said FAIL, and the commit proceeded because the pipeline's exit status was
  `tail`'s. At `89d0a78` the same gate exits **0**.
- **Why it matters — and why it generalises.** This is not about the allowlist or the
  amendment. It is that **a gate invoked through a display filter reports the filter, not the
  gate**, and POSIX `sh` is last-command-wins by default. *Every* `| tail` / `| head`
  invocation of *every* gate in *every* batch of this project has the identical hole, and it
  fails silently in the safe-looking direction. A gate whose verdict a pipe can discard is a
  gate that only reports.
- **Suggested fix (three, in increasing order of strength).**
  1. `set -o pipefail` before any piped gate invocation.
  2. Run the gate bare, capture `$?`, branch on it, and only then display: `python enum.py > gate.log; rc=$?; tail -20 gate.log; [ $rc -eq 0 ] || exit 1`.
  3. **Preferred** — move the propagation gate into the RC-1 pre-commit hook, so shell
     plumbing cannot be the arbiter of whether a commit is allowed.
- **Yes, this deserves a carry of its own.** Proposed wording:

  > **`C-78-xx` — a gate invoked through a pipe reports the pipe, not the gate.** `enum.py`
  > exited **1** and the commit proceeded, because `python enum.py | tail && git commit`
  > takes its status from `tail`. Reproduced at `75c9714`: exit 1, one undispositioned hit.
  > The defect is neither the allowlist nor the amendment — it is that gates are run through
  > display filters in a shell whose default is last-command-wins. **Run gates bare and
  > branch on `$?`, use `set -o pipefail`, or move the gate into the pre-commit hook.**

### F-5 — the packet re-cites `markup=False` instead of re-deriving it — its own `C-78-xix` defect  ·  **[LOW]**

- **What.** `increment-004.md` §1.4 and the evidence checklist both cite **`:6767-6768`** for
  the `markup=False` construction, copied from `01-requirements.md:537`. Measured on this
  branch: **`:6770-6771`**.
- **Why it matters.** Small in itself. Notable because it sits in the *same paragraph* that
  corrects `_KIND_LABEL`'s stale citation (F-3) — one sibling figure was re-derived and the
  other carried forward unchecked, in a packet whose headline carry is *a carried number is
  re-derived, not copied*. Worth naming precisely because the increment coined the rule.
- **Suggested fix.** `:6767-6768` → `:6770-6771` in `increment-004.md` §1.4 and the checklist,
  and in `01-requirements.md:537`.

### F-6 — the stated reason for "no handler is displaced" is backwards  ·  **[LOW]**

- **What.** `increment-004.md:46` says the App-level handler *"returns for every list that is
  not `a2l_tags_list`"*. The body (`app.py:7495-7496`) is:

  ```python
  if event.list_view.id == "a2l_tags_list":
      return
  ```

  …and nothing after it. It returns **for** `a2l_tags_list` and falls off the end of an empty
  body for every other list.
- **Why it matters.** The conclusion is right — both paths are no-ops, so nothing is
  displaced, and I verified that independently (S-3). But a future auditor checking this
  claim against the code will find a direct contradiction and have to re-derive the whole
  question. The honest sentence is shorter: *"`app.py:7477`'s handler has no effect on any
  list; `screens.py:1981`'s belongs to `OperationsScreen(ModalScreen)`, not an ancestor."*

### F-7 — `int(item.id[len("diff_run_"):])` assumes a numeric tail the guard does not check  ·  **[LOW]**

- **What.** `screens_directionb.py:7086-7088`. The guard tests a *prefix*; the parse assumes the
  remainder is an integer. Any future id of the form `diff_run_*` with a non-numeric suffix
  raises `ValueError` inside a Textual message handler.
- **Why it matters.** Unreachable today — `_render_run_list` is the only minter and
  `_run_note_item` assigns no id at all — so this is a recommendation, not a defect. But
  guard and parse should agree, and a raise inside a message handler is a poor failure mode.
- **Suggested fix.** `m = re.fullmatch(r"diff_run_(\d+)", item.id or "")` / `if m is None: return` /
  `self._render_run_windows(int(m.group(1)))`. Costs one import the module may already carry.

### F-8 — `render_comparison` now renders run 0 twice, undocumented  ·  **[LOW]**

- **What.** `_render_run_list` ends with `listing.index = first_run_position`, which posts a
  `ListView.Highlighted` for `diff_run_0`; `render_comparison` then also calls
  `_render_run_windows(0)` directly (`:6932`).
- **Why it matters.** Not a bug — the render is idempotent and the final state is correct,
  and I would **keep the explicit call**, because dropping it would make the initial window
  depend on message-loop timing. But the redundancy is now invisible to a reader, and the
  next person to touch this will either delete the "dead" call or chase a phantom double-render.
- **Suggested fix.** One comment on `:6932`: *"also rendered by `on_list_view_highlighted`
  when the index assignment lands; kept explicit so the first window does not depend on the
  message loop."*

---

## The coordinator's Amendment D — reviewed as a change

**Verdict: the amendment is sound and I would take it. One claim in it is stronger than what holds.**

**The defect it names is real, and I confirmed it by measurement rather than by reading.**
At 132×44 the derived capacity is **12**, so a correct implementation emits twelve row
addresses and can never emit *exactly* three. `HLR-123`'s two clauses — *"always include the
run ± context"* and *"the row count derives from the pane height"* — have an empty
intersection wherever the derived count exceeds three, and 132×44 is the size §7 itself
names for this gate. **`AT-B78-22` as originally worded would have false-failed a correct
implementation.** Amending the requirement rather than the test is the right direction, and
the direction matters: relaxing a threshold to fit an implementation is how a gate stops
gating, and this is not that.

**"Nothing was weakened" — accepted, with one qualification.**

| Claim | Verdict | Evidence |
|---|:-:|---|
| The three literals are still asserted **exactly**, at content height 0 | ✅ holds | `assert short["rows_a"] == _B78_AT22_ADDRESSES` at 132×24 (`content_h == 0`, measured) |
| The exact arm still reddens under M2 | ✅ **executed** | M2 → `AT-B78-22` RED on `AssertionError: … expected [0FF0,1000,1010], emitted [0FF0,1000]` |
| The containment arm is inert under M2 | ✅ correctly declared | Under M2 at 132×44, `low` moves `0xFB0 → 0xFA0`; the emitted set still contains the three literals contiguously, so containment cannot redden |
| The inert arm is **labelled and not counted** as a discharge | ✅ holds | Amendment D says so; `increment-004.md` R-2 repeats it; §5.3's GATE/PIN census is unchanged |

**The qualification.** A *stronger* arm was available at 132×44 and was not taken. Asserting
the emitted set is exactly the twelve contiguous bases starting at **`0x00000FB0`** *would*
have reddened under M2 — I measured M2's start at `0x00000FA0`, one row lower, because the
surplus changes when `rows` drops from 3 to 2. So exactness at the tall pane is achievable;
what is unachievable is exactness *on the three literals*. The containment form trades that
discriminating power for stability against §3's own C-29 warning that US-78-1 will move any
absolute count — **a defensible trade, and not one I would block on**, but the amendment's
flat *"nothing was weakened"* is broader than what it establishes.

Related, and worth naming rather than hiding: exactness now lives only at a pane that paints
**nothing** (content height 0). The requirement's operator-facing observable — *"picking a
run shows that run's bytes"* — is never asserted exactly at a size an operator uses. It is
covered in aggregate by `AT-B78-22`'s contiguity check, `TC-B78-24` and `TC-B78-25`, so this
is not a gap, but it is a fact about where the gate's exactness sits.

**Recommended edit — one sentence, no structural change.** After *"Nothing was weakened…"*
add: *"The tall-pane arm is nonetheless weaker than the strongest available form — an exact
twelve-literal set at 132×44 would redden under M2 — and is chosen over it deliberately,
because §3's C-29 note forbids absolute counts that US-78-1 will move."* That converts an
overclaim into a recorded decision, which is the same move the amendment makes everywhere else.

---

## The coordinator's `enum.py` widening — reviewed as a change

**Verdict: legitimate. I applied your own test and reached your answer.**

The question you posed is the right one — *is the flagged hit current, correct content in a
section the term list never anticipated, or is a stale form being excused?* It is the first,
and four independent things say so:

1. **The hit is the current form, not a superseded one.** The single undispositioned hit is
   `01-requirements.md:894`, matching `high = end` — identical to the mutation §7 carries and
   to the one I executed as M2. It is not the retired `ctx 16 → 64` form.
2. **The STALE list was not touched, and that is where the anti-regression force lives.**
   `("ctx mutation for AT-B78-22", r"reddens under `ctx 16 → 64`")` remains zero-tolerance
   across the whole document. The `TERMS` allowlist is a *scope* check — "may this term
   appear here" — not a correctness check. Widening a scope while leaving the correctness
   guard untouched cannot turn a red into a green for the thing the guard exists to catch.
3. **§6.5 is already an allowed section for two other terms** (`_project_label` at `:59`,
   `shall outside Statements` at `:78`). This is consistency with the existing register, not
   a special case minted for one hit.
4. **It widens the rule, not the instance** — the project's stated preference (*general
   controls, not narrow patches*), and the same shape as the `C-78-xi` precedent the comment
   cites.

**One residual cost, stated so it is a decision and not a blind spot.** §6.5 grows with every
amendment, and the widening now permits *future* §6.5 text to restate this mutation in a
**new** wrong form without flagging — the STALE list only knows the wrong forms it has already
seen. That is an accepted, bounded risk, not a reason to revert.

**Where I do fault the sequence: not the widening, the swallowed exit code.** See **F-4**. The
allowlist edit is the correct response to a correct gate failure. Committing before making
it was possible only because a pipe ate the verdict, and *that* is the thing to carry
forward. Recording the widening in a comment rather than making it silently is exactly right
and I would keep that habit.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|:-:|---|
| Diff read in full | ✓ | `screens_directionb.py:7055-7175` · `test_tui_diff_screen.py:274-314, 1928-2563` · `01-requirements.md:298, 883-899` · `enum.py:65-79` · `increment-004.md` (301 lines). Every line number in this review was re-derived against `89d0a78`, not copied from the packet — six of my own first-draft citations were off by 1–3 and are corrected above. |
| Correctness pass (edge / None / error paths) | ✓ | `item is None` and id-prefix guards read (S-3) · address-0 clamp executed (S-5) · zero-height pane executed (S-1, 132×24/120×30/80×24) · `_runs` ordering in `render_comparison` (S-9) · `ValueError` tail-parse gap (F-7) |
| Simplicity pass (no premature abstraction) | ✓ | `min` judged and **kept** — the panes already disagree on width at 80×24 (S-4) · no new class, no new module, two methods and one f-string · the only new test driver is 4 lines and delegates to Inc-2's (`C-78-xiii` honoured) |
| Reuse / duplication checked | ✓ | Inc-2's `_b78_drive_compare` / `_b78_press_compare` / `_b78_focus_run_list` / `_b78_run_list` / `_b78_run_index` reused verbatim; no fourth driver copy · `size.height` is the production idiom, Inc-1's `_b78_painted_content_height` correctly left in the test layer |
| Tests reviewed for intent, not just behavior | ✓ | **10 mutations executed**, 4 declared + **6 of my own**; 4 of mine left 10/10 green → **F-1** (HIGH), **F-2** (MEDIUM). Every node's docstring states WHY, and the `_B78_AT22_ADDRESSES` literals correctly avoid the F-6 `f(x)==f(x)` shape |
| Counterfactuals applied-checked and sha-restored | ✓ | 10/10 `APPLIED=True`; every sha distinct from its predecessor; `FINAL sha=2429d588ed343e44 == baseline` in both harness passes |
| Mutations run in a throwaway copy | ✓ | detached worktree `scratchpad/wt78` at `89d0a78`; operator tree never written; `prototypes/memmap2.*` untouched; no `git add -A`, no `git stash` |
| Verdict explicit | ✓ | below |

---

## Verdict

- [ ] OK to advance
- [ ] OK with the listed fixes applied first
- [x] **Block — must fix the HIGH finding before advancing**

**Blocking on F-1 only.** The implementation is correct — I measured the centring working
(13 above / 14 below of 28 at 132×60) and could not break the shipped behaviour with any of
my ten mutations. What blocks is the **claim**: `A-6` is reported discharged and queued to be
marked in §8, and nothing that can fail protects the arithmetic it names. Marking it removes
it from scrutiny permanently. The fix is the six-line assertion in F-1, which I executed
against baseline, R5 and R6 — it passes on the shipped tree and reddens on both mutations.

**F-2, F-3 and F-4 are recommendations, not blockers,** but F-3 (the `C-78-xviii` collision)
should be resolved in the same edit because it costs one line and silently loses a carry
otherwise, and F-4 deserves to be raised to the operator as a carry regardless of this gate.

**Not manufactured, and stated plainly:** `AT-B78-20`, `AT-B78-21` and `AT-B78-22` are all
genuine gates. Every declared counterfactual reddens on its own assertion with no
`TypeError`, no import error and no driver failure — the `C-78-xv` defect that cost Inc-3 its
`LLR-122.4` discharge did not recur. All three suites reproduce to the test. The Amendment is
right and the widening is legitimate. **This is a clean increment with one over-claimed
discharge in it.**
