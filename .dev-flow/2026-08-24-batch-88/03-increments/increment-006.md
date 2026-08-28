# Increment 006 — `HLR-88.6` / `LLR-88.12` — the imaging dependency reaches the job that needs it

> **⚠ C-56 SUBSTITUTION IN THIS PACKET, inherited from Inc 4 and Inc 5.**
> Acceptance ids are written with the prefix `ID-`. Spelling the real prefix here would re-declare
> the id into `_atlas_id_scan`'s `batches` realm — de-minting from one rule's population is
> RELOCATION into another's. Measured after writing: the gate is unmoved at `3 block · 287 notice`.

> **⚠ REVISION 2, 2026-08-27. This packet was BLOCKED at HIGH on its first draft for documenting a
> change that was not on disk.** The operator widened the guard line and re-authored `ID-B88-09`
> *after* the evidence was gathered, and the packet was not regenerated — so it quoted a narrow
> guard, called two edited records unedited, and listed three completed items as pending. **The
> load-bearing consequence was not the prose: the negative control and the hazard simulation had
> been executed against a line that no longer shipped.** Both were re-run against the shipped line
> and their transcripts are in §3. Everything a reader is asked to trust here is stated against
> `git`-verified disk state as of this revision.

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `006` of 7 |
| Requirement(s) | `HLR-88.6` · `LLR-88.12` |
| Acceptance | `ID-B88-09` (+ `ID-B88-08`, the source pin, re-measured) |
| Date | `2026-08-27` (rev 2) |
| **Kind** | **The first increment of this batch that touches the PRODUCT repo, not the validator.** No arms were added; the evidence is an acceptance executed by installing. |

---

## 1 · What changed

**The imaging dependency stopped being a line in a CI script and became a declared tier of the
manifest — and the job that needs it now reads that tier.**

`pyproject.toml` gains a third optional-dependency table, `evidence`, holding exactly one entry,
`pillow>=10`, with a rationale comment in the house style of `[project].dependencies`.
`.github/workflows/tui-ci.yml`'s `tui-ci` job stops installing `pillow` out of band and installs
`-e ".[evidence]"` instead, followed by one import guard.

### The tier, and why it is not `dev`

`M-12` measured it and this increment re-measured it by executing both extras. The `dev` extra
pins `textual==8.2.8` for renderer-sensitive SVG baselines. Routing `tui-ci` through `dev` to
obtain the imaging library would have pinned the renderer under the full suite that job collects
on push. Measured, in fresh venvs built from a byte-identical copy of this manifest:

| Install | `PIL` | `pytest_textual_snapshot` |
|---|---|---|
| `-e ".[evidence]"` | **12.3.0** | `ModuleNotFoundError` |
| `-e ".[dev]"` | **`ModuleNotFoundError`** | present |

**The extras are disjoint in BOTH directions**, which is a stronger statement than the acceptance
asked for and settles the tier question by execution: `dev` alone would not have given the
`tui-ci` job the imaging library at all.

### The floor, and what it does NOT claim

`pillow>=10` — not bare, not pinned; **the value is operator-ruled and is untouched here.** What
changed in this revision is the **comment beside it**, because the comment claimed more than the
specifier delivers.

The decoder-CVE argument does **not** apply and the security lens verified rather than assumed
that: the GIF test synthesizes buffers, and its only `Image.open` reads PNGs the same test wrote
seconds earlier under `tmp_path`. The floor is owed as a **major-version and reproducibility**
floor — it excludes 9.x and refuses the specifier-less style this batch registers as `R-88-6`.

**It does NOT assert a vendored-library patch level, and the first draft's comment said it did.**
`>=10` admits `10.0.0`, and every vendored-library bump the argument gestures at lands *above* it,
so the guarantee is empty inside the admitted range. **Executed, not argued** (§3, F2): with
`pillow 10.1.0` already installed, `pip install -e ".[evidence]"` reports `Requirement already
satisfied` and leaves it — pip's `only-if-needed` strategy does not pull a satisfying old version
forward. `>=10.3` is the smallest value that would deliver the stated guarantee; raising it needs
a ruling and is filed in §5.

### The guard, what it costs, and what it does not reach

One line, immediately after the install, inside the same `run:` block — **quoted from disk at
`tui-ci.yml:41`:**

```yaml
          python -m pip install -e ".[evidence]"
          python -c "from PIL import Image, ImageDraw, ImageFont; import PIL; print(PIL.__version__)"
```

The reroute trades a loud failure for a silent one: today a mistyped package name fails the step;
after the reroute a mistyped **extra** exits 0. **Simulated end to end against the shipped line**
(§3, E6): `pip install -e ".[evidenc]"` exits **0**, and the guard on the next line exits **1**.
Because GitHub Actions runs `run:` blocks under `bash -e`, that non-zero exit fails the step — at
install time, on the PR, instead of post-merge on `main` where the `slow` marker would hide it.

**The widening closes ABSENCE, not BREAKAGE, and the difference is measured** (§3, F3). It is
recorded as open, not fixed; a further widening is the operator's to rule.

---

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `C:\Users\jjgh8\Github\s19_app\pyproject.toml` | **source** | new `evidence` table; **24 lines added, 0 removed** (17 in rev 1 + 7 from the F2 comment correction) |
| `C:\Users\jjgh8\Github\s19_app\.github\workflows\tui-ci.yml` | **source** | `tui-ci` job only: install rerouted, 3 ad-hoc lines removed, 1 guard added |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-08-24-batch-88\01-requirements.md` | record | `ID-B88-09`: two new ⚠ bullets (operator, rev 1) + this revision's F3/F4/F5 corrections; `HLR-88.6` + `LLR-88.12` thresholds; criterion 8 |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-08-24-batch-88\02-review-security.md` | record | pip-warning surface refinement (operator, rev 1); F2 heading corrected; the ruled guard line marked superseded as a quotation |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-08-24-batch-88\03-increments\00-increment-plan.md` | record | Inc 6 row: superseded ruling struck, EDITS clause appended — **by supersession, not rewrite**, because §2b forbids editing the baseline to match what happened |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-08-24-batch-88\03-increments\increment-006.md` | record | this packet |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\_derived\` | derived | Atlas regenerated with `--atlas --write` **after** this packet existed |

| **SOURCE files** | **`2`** — `pyproject.toml` and `.github/workflows/tui-ci.yml`. Four records and the derived Atlas are not source. |
|---|---|

**⚠ The first draft's file table listed only the two source files and was wrong**: `01-requirements.md`
and `02-review-security.md` were already modified in the tree when it was written. Six authored
files is above this batch's habitual shape; the four record edits are coordinator-directed
corrections to documents this increment is measured against, and are named rather than folded into
the source count.

```
 .dev-flow/2026-08-24-batch-88/01-requirements.md   | 33 +++++++++++++++-------
 .../2026-08-24-batch-88/02-review-security.md      | 20 +++++++++----
 .../03-increments/00-increment-plan.md             |  4 +--
 .dev-flow/_derived/ATLAS-BATCHES.md                |  2 +-
 .dev-flow/_derived/ATLAS-IFC.md                    |  2 +-
 .dev-flow/_derived/ATLAS-ORPHANS.md                |  2 +-
 .dev-flow/_derived/ATLAS-TRACE.md                  |  2 +-
 .github/workflows/tui-ci.yml                       |  6 ++--
 pyproject.toml                                     | 24 ++++++++++++++++
 9 files changed, 70 insertions(+), 25 deletions(-)
```

**Nothing was committed.** `prototypes/`, `build/`, `s19_app/`, `tests/`, `tools/` and every
untracked file were left alone.

---

## 3 · Test results

### The manifest, parsed rather than eyeballed

`tomllib` over the post-edit file:

```
dependencies: ['rich>=13.0', 'textual>=8.0.2', 'markdown-it-py>=3']   n = 3
extras: ['dev', 'evidence']
  dev:      2 -> ['pytest-textual-snapshot==1.1.0', 'textual==8.2.8']
  evidence: 1 -> ['pillow>=10']
```

**3 / 2 / 1**, exactly the threshold, and `pillow>=10` unchanged by the F2 comment correction.
`[project].dependencies` and `dev` are byte-identical **by construction, not by inspection**:
`git diff --numstat -- pyproject.toml` reports `24  0` — **zero deleted lines anywhere in the
file**, so no pre-existing byte moved.

### The workflow diff

```
--- a/.github/workflows/tui-ci.yml
+++ b/.github/workflows/tui-ci.yml
@@ -37,10 +37,8 @@ jobs:
           python -m pip install --upgrade pip
           python -m pip install -r requirements.txt
           python -m pip install pytest
-          # Test-only dependency: tests/test_examples_pilot_gifs.py imports
-          # PIL to render the example GIFs (dev tooling, not a runtime dep).
-          python -m pip install pillow
-          python -m pip install -e .
+          python -m pip install -e ".[evidence]"
+          python -c "from PIL import Image, ImageDraw, ImageFont; import PIL; print(PIL.__version__)"
```

**One file, one hunk, in the `tui-ci` job only.** `git diff --name-only -- pyproject.toml .github/`
returns exactly those two files. **The unscoped `git diff --name-only` returns 9** — the first
draft cited the unscoped command for a scoped claim, which is the same defect class as the rest of
its F1. The `snapshot` job's `.[dev]` install is **byte-identical and absent from the diff**; its
line number moved `:76 → :74` because two net lines were removed above it. The workflow re-parses
under `yaml.safe_load`; both jobs and all five `tui-ci` steps survive.

**⚠ THE "5" IS AN ENUMERATION OF EDITS, NOT A GIT LINE COUNT.** `git diff --shortstat -- .github/`
reports **`1 file changed, 2 insertions(+), 4 deletions(-)`**. The threshold's five are the five
edits it names — one line rerouted (which git renders as a delete plus an add), three removed, one
added — and every one is present with no sixth. **Widening the guard did not change this shape**;
it is the same 2/4 as at rev 1. The disambiguating clause is now written into all five sites that
carried the ambiguous form (`HLR-88.6`, `ID-B88-09`'s deliverable, `LLR-88.12`, criterion 8,
`00-increment-plan.md`).

### The evidence arms — RE-RUN AGAINST THE SHIPPED GUARD LINE

The line was **extracted from the workflow by `yaml.safe_load`**, not retyped, and executed
verbatim:

```
SHIPPED GUARD, extracted from the workflow:
python -c "from PIL import Image, ImageDraw, ImageFont; import PIL; print(PIL.__version__)"
```

All environments were **throwaway venvs under `~/.claude/jobs/c0c0fa47/tmp/`**, deleted afterward,
built from a **byte-identical copy** of this manifest (verified equal) plus `README.md` and
`s19_app/`. **The operator's Anaconda environment was never mutated** and the live repository never
received an `-e` build artifact. Each venv was first proven blind to the machine's own PIL 12.2.0.

**E1 — the negative control, the arm `ID-B88-09` calls the one it is worthless without:**

```
### venv blind to the machine's PIL?
ModuleNotFoundError: No module named 'PIL'

### E1 NEGATIVE CONTROL, bare -e .
INSTALL_EXIT=0
--- shipped guard line, verbatim:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'PIL'
GUARD_EXIT=1
```

**E6 — the hazard simulation, the extra mistyped as it would be by a typo or a rename:**

```
### E6 HAZARD SIMULATION, extra mistyped as [evidenc]
WARNING: s19tool 0.1.0 does not provide the extra 'evidenc'
INSTALL_STEP_EXIT=0
--- shipped guard line, verbatim:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'PIL'
GUARD_EXIT=1
```

**E2 — the positive, for completeness, also re-run:**

```
### E2 POSITIVE, .[evidence], shipped guard
INSTALL_EXIT=0
12.3.0
GUARD_EXIT=0
```

| # | Arm | Result |
|---|---|---|
| **E1** | **NEGATIVE CONTROL** — bare `-e .` + shipped guard | install **exit 0**; guard **exit 1** ✅ re-run |
| **E2** | positive — `.[evidence]` + shipped guard | `12.3.0`, exit **0** ✅ re-run |
| **E3** | disjointness — `pytest_textual_snapshot` in E2's venv | `ModuleNotFoundError` |
| **E4** | contrast — `.[dev]` | `textual 8.2.8`; **`PIL` absent** |
| **E5** | **floor vs pin, discriminating** | seeded `textual==8.0.2`: `.[evidence]` **leaves 8.0.2**; `.[dev]` **uninstalls it, installs 8.2.8** |
| **E6** | **hazard simulation** + shipped guard | install **exit 0**; guard **exit 1** ✅ re-run |

**E5 exists because `ID-B88-09`'s stated method does not work today** (§4). Seeding an older
`textual` and observing whether each extra *moves* it discriminates a floor from a pin structurally,
independent of what the index serves. The operator has since written this method into the
acceptance itself.

### F2, executed — the floor does not deliver the guarantee its comment claimed

```
### seed an OLD pillow that still satisfies >=10
seeded: 10.1.0
### now install .[evidence] over it
Requirement already satisfied: pillow>=10 in ...\vf2\lib\site-packages (from s19tool==0.1.0) (10.1.0)
### resolved:
after .[evidence]: 10.1.0
```

`10.1.0` rather than `10.0.0` because 10.0.0 ships no cp312 wheel; the mechanism is identical and
the point survives — **any** satisfying old version is left in place. The CVE-to-release mapping
behind the reviewer's finding remains **INFERRED** (no network was used, here or there); the pip
*behaviour* is now **VERIFIED**.

### F3, executed — the widened guard passes while the consumer breaks

Read from installed source first: `PIL/ImageFont.py:66-70` binds `core: ModuleType | DeferredError`
and, on `ImportError`, stores `DeferredError.new(ex)`, whose `__getattr__` defers the raise to first
attribute access; `FreeTypeFont.__init__` (`:255`) then does `raise core.ex`. The consumer
(`tests/test_examples_pilot_gifs.py:119-128`) wraps `ImageFont.truetype(...)` in `except OSError`.

Then **executed** — Pillow 12.3.0, `_imagingft` blocked by a meta-path finder:

```
GUARD OUTPUT: 12.3.0
GUARD RESULT: passed with freetype broken
CONSUMER RESULT: UNCAUGHT ImportError: DLL load failed while importing _imagingft (simulated broken freetype)
is OSError? False
EXIT=0
```

**The guard is green and the consumer raises uncaught.** Recorded as open beside `R-88-4`; the
guard was **not** edited again.

### `ID-B88-09`'s error arm, re-measured on both surfaces

```
$ pip install --dry-run --no-deps -e ".[definitelynotanextra]"     # dry-run surface
Would install s19tool-0.1.0
EXIT=0
$ pip install -e ".[evidenc]"                                       # real install path
WARNING: s19tool 0.1.0 does not provide the extra 'evidenc'
EXIT=0
```

**Same pip 24.2, two surfaces, one warning and one silence — exit 0 on both.** The record said
"no warning about the extra at all (newer pip emits a WARNING)", attributing to a future pip what
the shipped one already does on the real path. Corrected at **both** sites this revision:
`02-review-security.md` had it; `01-requirements.md`'s error arm — **the site the gate reads** —
did not.

### `ID-B88-08` — the source pin, and its negative control

```
$ git diff --stat 4131a384 -- s19_app/ tests/ tools/
(empty)   count: 0
$ git diff --name-only 4131a384 -- s19_app/ tests/ tools/ .dev-flow/ | wc -l
17
```

**0 files** under the three pinned source paths; non-empty when `.dev-flow/` is added — proof the
diff command is not silently a no-op.

### The gate, unmoved

| | Baseline | This revision |
|---|---|---|
| Gate | `3 block · 287 notice · 14 not applicable` | see §Report — measured after every edit |
| Block rows | `V7` hash drift · `V16` ×2 | the same three, verbatim |
| Selftest | `SELFTEST PASSED`, **376** arm lines | **376**, exit 0 |

**No arms were added and none was expected to be**: this increment does not touch the validator.
The validator exits **1** in both states — the three blocks are the flow-repo lifecycle (`V7` waits
for Inc 7's bump; `V16` ×2 is this batch's own uncommitted work), not content.

---

## 4 · Risks, and the things I could NOT arm

- **THE PROXY REPLACED THE EXACT ARTIFACT THE FLOOR'S ARGUMENT IS ABOUT.** The first draft said the
  evidence "ran against a copy, and against the wrong platform" and stopped there. That stops one
  step short. Enumerate the axes on which proxy and target differ, then ask whether any *claim's
  justification* sits on one:
  | Axis | Proxy | Target (CI) | Does a claim rest on it? |
  |---|---|---|---|
  | source tree | byte-identical manifest copy | the checkout | no — resolution is a pure function of the manifest |
  | OS / interpreter | Windows / CPython 3.12 | `ubuntu-latest` / 3.11 | no for E1–E6; extras resolution is platform-independent |
  | **wheel artifact** | `pillow-12.3.0-cp312-cp312-**win_amd64**.whl` | `manylinux` | **YES — and it is the whole floor argument** |
  E1–E6 transfer. **The manylinux-vendoring rationale does not**, because a `win_amd64` wheel has
  no manylinux vendoring at all: the evidence ran on the one platform where the argument does not
  exist. That rationale has now been **removed from the manifest comment** (F2) rather than left
  standing on evidence that could not reach it. The residual claim — `>=10` is a major-version and
  reproducibility floor — is platform-independent and is what the comment now says.
- **`ID-B88-09`'S ORIGINAL DISCRIMINATION METHOD WAS UNSATISFIABLE, AND THE WORLD WAS NOT ADJUSTED
  TO THE TEXT.** A fresh `.[evidence]` install resolves `textual` to exactly **`8.2.8`** — 8.2.8 is
  currently the newest release, so an unbounded floor and a pin land on the same string. The
  structural claim is TRUE and E5 establishes it by seeding. **The first draft reported this and
  declined to edit the acceptance; the operator has since written E5's method into it.**
- **`F3` IS OPEN, NOT FIXED, AND THE GUARD WAS NOT EDITED AGAIN.** The widened guard closes the
  three names being **absent**. It does not close the extension being **broken**: `from PIL import
  ImageFont` succeeds under a `DeferredError`, and the consumer's `except OSError` does not catch
  the `ImportError` that `FreeTypeFont.__init__` re-raises. Executed, §3. A further widening is the
  operator's to rule, because the current line is his.
- **THE SHIPPED GUARD CARRIES NO RULING CITATION.** The 2026-08-26 ruling names the narrow line
  verbatim at two sites; the shipped line differs. Both quoting sites are now marked **superseded
  as quotations of the shipped line**, and the citation slot is left as `‹ruling id owed›` for the
  operator rather than filled by me with a ruling that was not made.
- **`R-88-8` recurs, a FOURTH time, and this revision is its own evidence.** The threshold said
  "exactly 5 changed lines"; git says 2 insertions and 4 deletions. Nothing was wrong with the
  change — the counts answer different questions — but the ambiguity survived into **five** separate
  sites and was corrected in all five only after an independent review named them. A criterion whose
  satisfaction requires a paragraph of arithmetic gets reported as satisfied without one.
- **TWO REFINEMENTS EACH LANDED AT ONE SITE OF SEVERAL, AND THIS IS NOW THE BATCH'S THIRD INSTANCE.**
  The pip-warning correction reached `02-review-security.md` and not `01-requirements.md`'s error
  arm — **the site the gate reads**. The EDITS disambiguation reached `HLR-88.6` and not the other
  four. The shape is not "a correction was missed"; it is **"a correction has a population, and
  nothing enumerates it."** There is no rule that finds the other occurrences of a sentence being
  corrected, and this batch has now paid for that three times.
- **`pillow>=10` has no ceiling and no effective patch floor.** CI will take whatever the index
  serves for a fresh environment, and will leave any satisfying old version already present.
  Accepted because the consumer is one `slow` test and the value is ruled; `>=10.3` is filed.
- **Nothing in this increment is armed by the selftest, and nothing can be.** The subject is a
  package manifest and a CI workflow; the validator has no rule that reads either. The evidence is
  executed installs, and if they are not re-run the claims rot silently — **which is exactly what
  happened between rev 1 and rev 2**, when the guard line moved under an already-written packet and
  376 green arms noticed nothing. **There is no harness behind this increment**, said plainly.

---

## 5 · Pending

**Done since rev 1, and no longer pending** (the first draft listed all three as open, wrongly):
~~guard widening~~ · ~~`ID-B88-09` re-authoring~~ · ~~the pip-warning path qualification~~.

- **`F3` — the guard still does not close extension breakage.** A further widening (e.g. touching
  `ImageFont.load_default()`, which forces the deferred raise) would close it. **Needs an operator
  ruling**; the line is his and this increment did not touch it again.
- **`pillow>=10.3` is the smallest value that would deliver the vendored-library patch reading.**
  The comment no longer claims that reading, so nothing is currently false. Raising the floor
  **needs a ruling**. The CVE-to-release mapping behind it is **INFERRED** — no network was used.
- **The shipped guard's ruling citation is an empty slot** at three sites (`01-requirements.md`'s
  guard bullet, `02-review-security.md`'s mitigation, and the superseded quotations). For the
  operator to fill.
- **`requires-python = ">=3.8"` is still FALSE** (`R-88-7`; the real floor is 3.10, and
  `project.toml` must move with it). Not repaired here.
- **`requirements.txt` remains a third, disagreeing declaration surface** (`R-88-6`). Untouched,
  still harmless by ordering alone: installed at `:38`, before the project install.
- **`README.md` documents `pip install -e .` (`:60`) and `.[dev]` (`:66`) and neither yields the
  imaging library**, so a contributor who follows it and runs `pytest -q` errors on the GIF test.
  **Outside `LLR-88.12`'s population — noted, not fixed.** `.[evidence]` belongs in that list.
- **`00-increment-plan.md`'s execution ledger still shows `4 | next` and `5 · 6 · 7 | not started`.**
  Inc 4, 5 and 6 have all run. Not corrected here: §2b declares that table the baseline, and the
  two edits this revision made to it were supersessions of *withdrawn rulings*, not status updates.
- **The GIF suite itself has not been run.** `ID-B88-09` observes the environment. A passing
  `pytest -m slow tests/test_examples_pilot_gifs.py` transcript still does not exist.
- `V7` stays red until Inc 7's bump, by design. `V16` ×2 is this batch's own uncommitted work.
  **Nothing was committed.**
- The derived Atlas was regenerated with `--atlas --write` AFTER this packet existed.

---

## 6 · Suggested next task

**Inc 7** — Story C: `V25`'s four outcomes (`LLR-88.13`), its arms **and the COMPUTED exemption
set** (`LLR-88.14`), the INTAKE row (`LLR-88.15`), and the rev47 bump + re-hash (`LLR-88.16`).
Carry-overs:

1. **Bump LAST and re-hash, or `V7` reports drift that does not exist.** `V7` is red right now for
   exactly that reason; Inc 7 clears it, and the order of its own steps decides whether it does.
2. **The non-empty arm is the whole point of the derived exemption set.** A derivation that always
   returned `∅` passes every check written over it — the same vacuity, one layer up.
3. **A CORRECTION HAS A POPULATION, AND NOTHING ENUMERATES IT — this is the batch's strongest
   candidate for a new rule.** Three instances now: the pip-warning refinement, the EDITS
   disambiguation, and the guard line itself, which changed in the workflow while four documents
   went on quoting the old one. `V22`/`V23` already sweep the corpus for id-shaped things; the
   missing rule sweeps for **a corrected sentence's surviving twins**. Batch-89.
4. **`R-88-8` should be generalised, not just re-instanced.** Its siblings this batch: a version
   equality standing in for a constraint (`!= 8.2.8`), and a specifier standing in for a patch
   level (`>=10`). All three are *"a cheap proxy written before the thing it measures was
   designed."* One lesson, not three findings.

---

## Increment gate checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | **2** source — `git diff --name-only -- pyproject.toml .github/` returns exactly those two. ⚠ The unscoped `git diff --name-only` returns **9**; rev 1 cited the unscoped command for this scoped claim and was wrong. Four records + derived Atlas are named in §2, not folded into the count |
| 2 | Tests in the same increment | **n/a, and stated** | No arms added; the validator is untouched. Selftest **376 → 376**, `SELFTEST PASSED`, exit 0 — unchanged is the *expected* result. §4 states there is no harness behind this increment |
| 4 | RED counterfactual | ✓ | **E1** and **E6**, both **re-run against the guard line extracted from the workflow by `yaml.safe_load`**, in venvs proven blind to the machine's PIL: guard **exit 1** in both. Transcripts pasted in §3 |
| 5 | Reverse census | ✓ | Whole-repo: the **only** importer is `tests/test_examples_pilot_gifs.py` (`:111`, `:164`, function-local). `pillow` in the manifest exactly **1×**; in `.github/` **0×** after the edit. `find .github -type f` = **2** files, 1 changed |
| 9 | Coverage verified on disk | ✓ | `tomllib`: **3 / 2 / 1**, `pillow>=10` unchanged. `git diff --numstat pyproject.toml` = `24 0` — **0** deleted lines, so `dependencies` and `dev` are byte-identical by construction. `snapshot`'s `.[dev]` absent from the diff |
| 10 | Load-bearing emptiness | ✓ | E3 and E4 assert **absence** in both directions — the extras are disjoint, not merely differently populated. F3 asserts the opposite state: a guard that is **green while the thing it guards is broken** |
| 11 | Mutation verdicts per arm | ✓ | E5 is the discriminator (seeded `textual` survives `.[evidence]`, is uninstalled by `.[dev]`). F2 and F3 are executed counterfactuals, not readings: an old satisfying `pillow` is left in place; a blocked `_imagingft` leaves the guard green and the consumer uncaught |
| — | Record ↔ disk agreement | ✓ | **The item rev 1 failed.** Guard quoted from `tui-ci.yml:41` via `yaml.safe_load`; file table taken from `git diff --name-only`; diff shape from `--shortstat`; every completed item moved out of §5 |
| — | Environment safety | ✓ | Throwaway venvs under `~/.claude/jobs/c0c0fa47/tmp/`, **all deleted**; installs ran against a byte-identical **copy**; the operator's Anaconda install was never touched |
| — | Secrets | ✓ | no key, token, `.env` or credential read, written or printed; the change adds no `env:`, no `secrets.`, no network egress path |
| — | Destructive commands | ✓ | none run; `prototypes/`, `build/`, `s19_app/`, `tests/`, `tools/` and all untracked files untouched; **no commit** |

**An item without a citation is not satisfied — it is asserted.**

---
