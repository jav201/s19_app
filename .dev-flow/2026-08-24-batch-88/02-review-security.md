# Security Review — batch-88 (Inc 6: the `evidence` optional-dependency extra + the CI reroute)

> **VERDICT: `safe with conditions`.** 0 blockers · 0 major · 2 medium, **both dispositioned by
> operator ruling 2026-08-26**. F1 accepted and specified (`pillow >= 10`, floor + rationale);
> **F2 accepted as a KNOWN RISK, deliberately, with the mitigation declined** to hold the CI edit at
> four lines — recorded at the acceptance it weakens, not in a backlog.
>
> **This record discharges condition C9** of the station-4 design review sealed **2026-08-25**,
> which withheld Inc 6 until
> the lens ran. C9's subject was *"the dependency diff"*. **The diff does not exist**, so the subject
> reviewed is the change **as specified** — stated here rather than quietly substituted.
>
> ⚠ **That design record's id is DESCRIBED above, not written, and the reason is this batch's own
> subject.** Writing it bare mints a V23 notice: the shipped grammar admits a decision *inside* a
> record and cannot express a reference to the record *itself*. So the artifact discharging a
> condition cannot cite the record that imposed it — measured here, by tripping it. `LLR-88.9`
> repairs exactly this, and until Inc 2 lands, C-56 elision is the only conforming way to say it.

---

## Scope reviewed

| Item | Read |
|---|---|
| `pyproject.toml` | full, 62 lines |
| `.github/workflows/tui-ci.yml` | full, 79 lines |
| `.github/workflows/snapshot-regen.yml` | full, 60 lines |
| `requirements.txt` | full, 4 lines |
| `tests/test_examples_pilot_gifs.py` | the imaging call sites and the `slow` marker |
| `01-requirements.md` | `HLR-88.6`, `LLR-88.12`, `AT-B88-09`, `M-12`, criterion 8, `R-88-6` |
| `03-increments/00-increment-plan.md` | Inc 6 |

Swept: whole-repo grep for the imaging package and its import name; whole-`.github/` grep for
`secrets.`, `env:`, `token`, `pull_request_target`, `persist-credentials`, `uses:`;
`find .github -type f`.

**Blast radius, stated once.** A test-time dependency in an ephemeral GitHub-hosted runner holding
`contents: read` and **no secrets**. It never enters `[project].dependencies`, so the shipped
runtime footprint is unchanged. Worst case for a hijacked release: arbitrary code in a runner with
no credentials and no write path to the repository — **which is already the blast radius of
`pip install -e .` on the same line today.**

---

## Findings

### F1 — a specifier-less entry, in the batch that registers specifier-lessness as a defect  [MEDIUM · ACCEPTED, specified]

`HLR-88.6` and `LLR-88.12` specified *"exactly 1 entry"* and named no version specifier. The project
has two written conventions and this would have been a third: `[project].dependencies` uses floors
with rationale comments (`pyproject.toml:17-29`); the `dev` extra uses exact pins with a five-line
rationale (`:36-45`). And `R-88-6` in this very batch registers a **floorless** declaration in
`requirements.txt` as a defect that waits — a second one in the same commit would be the rule
contradicting itself.

**The decoder-CVE argument does NOT apply here, and the lens verified rather than assumed it.** The
imaging library decodes nothing hostile: the test synthesizes buffers (`Image.new`), draws with
program-generated strings, encodes to PNG, and the only `Image.open` reads PNGs **the same test
wrote seconds earlier in the same process** under `tmp_path`. The only foreign bytes are a
runner-supplied system font.

**The floor is owed for a different and more mundane reason that does bite:** manylinux wheels
**vendor** libjpeg-turbo, zlib, libtiff, libwebp and freetype, so the version specifier is the only
lever that can state "we are above patch X" of those C libraries. Floorless also means CI resolves
to whatever the index served that morning — the same non-reproducibility `pyproject.toml:38-43`
records having already burned this project once.

**Ruling 2026-08-26: `pillow >= 10`, floor plus rationale comment.** The one hesitation was
`requires-python = ">=3.8"` (Pillow 10.4 is the last line supporting 3.8). **Measured, and the
hesitation dissolved — see `R-88-7`: that declaration is false.** Installed `textual` requires
`>=3.9,<4.0`, `rich` `>=3.9.0`, `markdown-it-py` **`>=3.10`**, and `s19_app/cli.py:220` uses PEP 604
at runtime with no `__future__` import. **The real floor is 3.10.** Threshold unchanged at exactly
one entry, so the floor costs the specification nothing.

### F2 — the reroute trades a loud failure for a silent one  [MEDIUM · ACCEPTED AS A KNOWN RISK, mitigation declined]

**Today** (`tui-ci.yml:42`): a mistyped package name fails the step with a non-zero exit. **After**
(`:43`, `".[evidence]"`): a mistyped or renamed extra **exits 0**.

The lens reported this as INFER. **It was then executed rather than left inferred**, and the
measurement is worse than the inference:

```
$ pip install --dry-run --no-deps -e ".[definitelynotanextra]"
Would install s19tool-0.1.0
EXIT=0
```
`pip 24.2` — **no warning about the extra at all.** Newer pip emits a `does not provide the extra`
WARNING, but **still exit 0**, and a warning does not fail a CI step. The exit code is the half that
carries the weight, and it is 0 either way.

**Why it compounds.** The consumer is `@pytest.mark.slow` (`tests/test_examples_pilot_gifs.py:183`)
and pull requests run `pytest -q -m "not slow"` (`tui-ci.yml:45-47`). So a broken extra **deselects
the only test that would notice**, every PR stays green, and the failure surfaces post-merge on
`main` as a hard `ModuleNotFoundError` — not a skip, because that file carries **0** import-skip
guards (`R-88-4`).

**The available mitigation** is one line after the install:
`python -c "import PIL; print(PIL.__version__)"`. It fails loudly at the install step and doubles as
the resolved-version evidence `AT-B88-09` already wants. **It would take the CI edit from 4 lines to
5**, colliding with the *"exactly 4 lines, and in no other line"* threshold in `HLR-88.6`,
`LLR-88.12` and criterion 8.

**Ruling 2026-08-26: hold at 4 lines, accept the risk.** Recorded in `AT-B88-09` beside the
acceptance it weakens, so the next reader meets it where it matters. **Re-openable at one line.**

**Correction this finding forced.** `AT-B88-09`'s error arm asserted *"an unknown extra name fails
loudly at install rather than silently installing the base project."* That is the **opposite** of
measured behaviour. It has been corrected to state what pip does. Under either ruling this
correction was mandatory: **an acceptance marked satisfied against behaviour that does not occur is
the exact defect this batch exists to end**, and it would have shipped inside the batch that ends it.

---

## Cleared explicitly, so an absent finding is legible rather than assumed

**A · Elevated-trust escalation — VERIFIED, no finding.** `tui-ci.yml:7-15` triggers on
`pull_request`, **not** `pull_request_target`; `:20-21` sets `permissions: contents: read` at
workflow level for both jobs; a grep across all of `.github/` returns **0** hits for `secrets.`,
`GITHUB_TOKEN` and `env:`. **There is nothing for a poisoned dependency to exfiltrate.** The
decisive point: `pip install -e .` at `:43` **already** executes the PR's own `pyproject.toml`
through the build backend and already resolves whatever that PR-controlled manifest declares.
Reading one more table from the same already-trusted file is a **trust delta of exactly zero**, and
the package is the same one line 42 installs today. The one workflow that mutates baselines
(`snapshot-regen.yml`) is `workflow_dispatch` only and unreachable from a PR.

*Improvement worth naming:* `:42` and `:43` are two separate resolver invocations today, where the
second can silently downgrade what the first installed. After the change they are one. **Strictly
better.**

**B · Extra disjointness — VERIFIED, no finding.** PEP 621 extras are independent tables;
`evidence` does not reference `dev`, so `.[evidence]` drags in neither the snapshot plugin nor the
`textual==8.2.8` pin. The `snapshot` job's `.[dev]` at `:76` is untouched and keeps its pin, which
is what `M-12` says it wants. **This is the correct tier** — routing `tui-ci` through `dev` would
have pinned the renderer under the tests `pytest -q` collects, which is the defect the ruling avoids.

**C · The third surface (`R-88-6`) — VERIFIED, safe to leave.** `requirements.txt` is installed at
`:38`, **before** the project install, in both jobs. The edit touches only `:43` and deletes
`:40-42`, all *after* `:38`, so the ordering that makes it harmless is unchanged. Nothing about
`evidence` reaches it.

*Named without escalating:* `AT-B88-09`'s assertion that `textual` resolves `>= 8.0.2` and is not
`8.2.8`-pinned **discriminates the `dev` pin from the `evidence` extra**, which is the contrast it
was minted for. It is **not** a version-safety check and must not be read as one — `requirements.txt`
is floorless, so CI takes whatever is newest.

**D · Removal risk — VERIFIED, no finding.** Whole-repo grep: the **only** importer of the imaging
library is `tests/test_examples_pilot_gifs.py`. No production code, no tooling, no other test. The
`snapshot` job never reaches it and runs on a separate runner anyway. `find .github -type f` returns
exactly **2** files — no dependabot config, no composite actions, no reusable workflows. `pip install
pytest` at `:39` is outside the deletion range and survives. **Deletion is clean.**

**Out of scope, not a condition:** `actions/checkout@v4`, `setup-python@v5` and
`upload-artifact@v4` are pinned to mutable major tags rather than commit SHAs, across both
workflows. Pre-existing, unrelated to this diff, batch-89+.

---

## Evidence checklist

| Item | State |
|---|---|
| Every finding carries what · where · why · smallest fix | ✓ F1, F2 |
| Severity assigned | ✓ 0 blocker · 0 major · 2 medium |
| Secrets in output | ✓ none — the `.github/` sweep found none to redact |
| New external action surface assessed | ✓ no MCP, no connector, no network egress, no auth path, no deploy path |
| INFER separated from VERIFIED | ✓ and F2's single INFER was **executed** before it was acted on |
| Axes with no finding stated explicitly | ✓ A–D above |
| Operator dispositions recorded with their date | ✓ both, 2026-08-26 |

**An item without a citation is not satisfied — it is asserted.**
