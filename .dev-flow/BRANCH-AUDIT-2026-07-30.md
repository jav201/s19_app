# Branch audit — 2026-07-30

**Why this file exists.** The repo carried **45 non-`main` branches**, most of them long spent. Before
deleting any, every branch was measured for content `main` does not have, so that *"we have the docs
in Obsidian"* became a checked claim rather than an assumption. **Two branches turned out to carry
something real**, and this file is where that knowledge lives once the branches are gone.

## Method (and the one place it nearly went wrong)

Three tests per branch, all executed against `origin`:

1. `git rev-list --count origin/main..origin/<b>` — commits ahead.
2. `git diff --diff-filter=A --name-only origin/main origin/<b>` — files that exist **only** on the branch.
3. The branch's PR history, cross-referenced by exact head-ref match.

⚠️ **A three-dot diff (`origin/main...origin/<b>`) measures from the merge-base and made three
branches look like they carried 16 000+ unmerged lines.** The two-dot diff shows the truth: `main`
has **4 149 lines more** than they do. Direction matters; the first reading was wrong.

⚠️ **The PR cross-reference initially reported "NO PR EVER OPENED" for all 45 branches.** That was
`grep -P` failing on the locale, not a finding — every line errored. Re-run with an exact-field `awk`
match, **41 branches have a MERGED PR**. A universal negative should always be suspected of being a
broken predicate.

## Verdicts

### ✅ Provably spent — 40 branches

MERGED PR **and** zero files unique to the branch **and** no commits after the merge date
(41 examined, 0 anomalies; the date comparison was positive-controlled against an ancient date to
prove it can fire).

### ⚠️ Superseded, but another lane's deliberate backups — 3 branches

`backup/batch-64-addendum-uncommitted` · `claude/batch-64-addendum-producer-bound` (PR #148 CLOSED) ·
`claude/batch-65-addendum-producer-bound` (no PR).

Their D1 addendum-bounding work **is** in `main` — it shipped as batch-65 PR #149 `b691f21` through
`claude/batch-65-code-lane`. The 141 lines they hold that `main` lacks are **older versions**, not new
ideas: e.g. `Input(placeholder="Search ASCII text", …)` (superseded by `OsClipboardInput` at
batch-67) and the pre-batch-70 `run_flow(event.flow, FlowContext(project_dir=project_dir))` handler.
**Zero unique value.** They are listed separately only because the `backup/` prefix signals a
deliberate keep and they belong to a parallel session's lineage.

### 📥 Value EXTRACTED — 1 branch

`feat/batch-52-crc-block` carried `.dev-flow/2026-07-22-batch-52/02-review.md` and `04-validation.md`,
which **PR #120 CLOSED without merging**, so they were in the vault but missing from the repo. Both
verified **byte-identical to the Obsidian copies** (2 693 B / 2 927 B) and copied into the repo by
this audit. Repo and vault are now symmetric for batch-52; the branch is disposable.

### ❗ Genuinely unique and referenced NOWHERE — 1 branch

`web/flask-viewer` — last commit **2026-04-13**, which predates `.dev-flow/2026-05-05-batch-01`, i.e.
the entire dev-flow record. **Mentioned in no backlog, no requirement, and no vault note.**

| | |
|---|---|
| `s19_app/web/` | `app.py` (`create_app`), `routes.py`, `loader.py`, `session_store.py`, `a2l_utils.py`, `mac_display.py`, `cli.py`, `__init__.py`, `templates/{base,index,view}.html`, `static/app.css` |
| `tests/test_web_app.py` | its own test module |
| Total | **1 187 lines** — a read-only Flask localhost viewer MVP |
| Junk it also carries | `debug-cdc3df.log` — a stray log, no value |
| **A real gap it fills** | `examples/case_04_bad_checksums/firmware.mac` — **`case_04` is the only example case in `main` with no `.mac` file** (7 of 8 have one) |

**Deleting this branch destroys 1 187 lines of working code that nothing else records.** It is the
only branch in the repo for which that is true.

## Disposition

- The 40 spent branches and `feat/batch-52-crc-block`: deletable — their value is either in `main` or
  extracted above.
- The 3 parallel-lane backups: superseded, but not this lane's to discard.
- `web/flask-viewer`: **held pending an operator decision.** Options are to revive it as a batch,
  archive the tree somewhere durable, or delete it knowingly. What must not happen is deleting it
  *unknowingly*, which is what this file prevents.
- `examples/case_04_bad_checksums/firmware.mac` is a **separate, much smaller question** and is
  carried in `BACKLOG-CODE.md` independently of the viewer's fate.
