# batch-76 — Phase 4 validation (merge-gate closure)

**Commit under test:** `fd9124a` · **Base:** `origin/main` = `291bb76` · **PR** [#184](https://github.com/jav201/s19_app/pull/184)

---

## §1 The one complete gate run, evidence read from its own output (C-19/C-25)

```
29 snapshots passed.
2514 passed, 2 skipped, 3 xfailed in 1734.87s (0:28:54)
exit 0
```

**Provenance, recorded BEFORE the run and in the same transcript** — because batch-76 already produced
one contaminated run by launching a suite while the mutation harness was writing to the same tree:

| Check | Value |
|---|---|
| HEAD at launch | `fd9124a`, committed |
| Working tree | clean except pre-existing untracked `prototypes/out/` |
| Launched | **after** the last edit, and after the last mutation |
| Concurrent mutation harness | **none** — the harness mutates a separate throwaway `git worktree`, so this class is removed by construction, not by sequencing |
| `report_service.py` sha256 | `8e2b8f4facf2f9e1…` |
| `test_report_document_bound.py` sha256 | `a40f27086a2334c2…` |
| `markdown_safety.py` sha256 | `88dcb2fb5c333018…` (unedited, spec P-4) |

Only **one** gate run was performed and it is the one cited. No run was discarded.

---

## §2 Ledger — `post = base − D + A`, and why the number is not 2493

The hand-off's baseline is **2482 passed / 2 skipped / 21 deselected / 3 xfailed**. This run reports
**2514 passed / 2 skipped / 0 deselected / 3 xfailed**. The naive expectation was `2482 + 11 = 2493`,
so the +32 needed explaining rather than accepting.

**Reconciled on collection totals, which is the invariant that matters:**

| | hand-off baseline | this run | delta |
|---|---:|---:|---|
| **collected** | 2 508 | **2 519** | **+11** — exactly this increment's new arms |
| passed | 2 482 | 2 514 | +11 new, **+21 previously deselected** |
| skipped | 2 | 2 | 0 |
| deselected | 21 | **0** | the 21 were executed here |
| xfailed | 3 | 3 | 0 |
| snapshots | 29 | 29 | 0 |

`D = 0`, `A = 11`, so `2508 − 0 + 11 = 2519` collected. **Nothing was deleted, renamed, or skipped to
reach green.**

**The +11, itemised** (file moves 27 → 38):

| node | before | after | delta |
|---|---:|---:|---|
| `TC-552` | 3 arms | 7 arms | +4 |
| `TC-555` | 1 node | 5 arms | +4 |
| `TC-611` | — | 2 arms | +2 |
| `TC-612` | — | 1 | +1 |

**The +21 is a coverage gap in the gate convention, not a change of mine.** Executed:
`pytest -m slow --collect-only` collects **exactly 21** of 2 519. `.github/workflows/tui-ci.yml:47`
runs `pytest -q -m "not slow"` on **pull requests** and `:51` runs the full `pytest -q` on **pushes**.
The batch's local gate evidence (Inc-1 `2455/2/21/3`, hand-off `2482/2/21/3`) therefore mirrored the
**lean PR** form, so **the 21 slow perf-smoke tests appear in no batch-76 gate evidence at all** — while
merging this branch to `main` triggers the **full** form that runs them.

This run used the full form deliberately. All 21 pass. The gap is closed **before** the merge rather
than discovered by the post-merge push job.

---

## §3 Counterfactual evidence — per resolved arm (§3 item 1)

Baseline is the **FIXED** tree; each mutation records the **substituted value**, not a deleted
operator; each is applied to a throwaway worktree and restored with the restore **verified by SHA-256**
returning to its pre-mutation value.

| # | Finding | Substituted | Arms | Verdict |
|---|---|---|---:|---|
| M1 | H-1 | `_EmissionGate.fits` body → `return True` | 7/7 | **ALL RED** |
| M2 | H-2 | `_disclosure_allowance` → `1_000_000_000 + variant_count` | 5/5 | **ALL RED** (cap) |
| M5 | H-2 | heading term → `len("## Variant: ") + REPORT_CELL_CHARS` | 5/5 | **ALL RED** (slope floor) |
| M6 | H-2 | block term `len(REPORT_SECTION_KINDS)` → `1` | 1/1 | **ALL RED** |
| M3 | H-4 | `f"bytes {refusals.byte_count…}"` → `f"bytes {sections}"` | 1/1 | **ALL RED** |
| M4 | H-3 | `md_safe` return → byte-truncated output | 2/2 | **ALL RED** |

**21 of 21 arms RED.**

**M1 is the finding, stated as the two harnesses report it:**

```
old harness:  M1  AT-250/251/252  RED   3 failed, 4 passed     -> recorded "RED, INERT: none"
new harness:  M1  RED  AT-250 · AT-251[10] · AT-251[100]
                  GREEN AT-251[1] · AT-252[1] · AT-252[3] · AT-252[10]   <- 4 inert arms
after H-1:    M1  RED  all 7
```

**Harness positive control (TC-554 pattern).** A substitution placed *after* the `return` is reported
**inert on all 5 arms AND "region NEVER EXECUTED"**. A harness that cannot tell dead code from a
passing guard would be the tool-level instance of the vacuous check it exists to find.

**Two of the six mutations reddened nothing on first run, and both faults were in tests written this
session** — `TC-612`'s probe label was 21 characters against an 18-character maximum (moving the
row-width term, not cardinality) and `TC-555`'s total floor was inert on 4 of 5 arms against a 2×
slope error. Both fixed; both re-executed to all-RED. Recorded because a harness whose first run is
all-green has demonstrated nothing.

---

## §4 Frozen set — both C-27 guards, not one

| Guard | Result |
|---|---|
| Frozen **SOURCE** diff vs `origin/main` (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, `markdown_safety.py`) | **empty** |
| Frozen **SOURCE** diff, working tree | **empty** |
| Frozen **TEST** guard — `tests/test_engine_unchanged.py` | **1 passed** |

`markdown_safety.py` is **unedited** (spec P-4). M4 mutates it only inside the throwaway worktree,
which is a counterfactual, not an edit — and the worktree was `git checkout -- .` reset before the
final matrix.

---

## §5 Dual traceability / registry

| Check | Result |
|---|---|
| G1–G7 guard (`tests/test_id_registry.py`) | **13 passed** |
| New ids | `TC-611`, `TC-612` — taken from `_meta.next_free`, no letter suffix |
| `high_water.TC` / `next_free.TC` | 610 → **612** / 611 → **613** |
| Re-pointed rows | `TC-552`, `TC-555` — renamed nodes, statements updated |
| C-18 (one id → exactly one node) | held; this is why the chartered `TC-555` discriminating arm was split to `TC-612` rather than added as a second node |
| `EXPECTED_SCANNED_TEST_FILES` | **152**, unchanged — no new test module |
| Registry diff | 5 insertions / 3 deletions over 1 373 rows; the other 1 368 byte-identical |

**Declared, not silent:** the `TC-555` → `TC-612` split is recorded in `increment-004.md` §3 and in the
amendment log. `TC-556`'s undeclared repurposing is the defect this contrast is drawn against.

---

## §6 Output neutrality of the one production edit

`REPORT_VARIANT_ID_MAX_BYTES` replaced `REPORT_CELL_CHARS` in two `_disclosure_allowance` terms.

| Evidence | Result |
|---|---|
| Production readers of the new constant | **only** `_disclosure_allowance` (`:881`, `:891`) |
| Production callers of `_disclosure_allowance` | **zero** (census over `s19_app/`, non-docstring) |
| `AT-256` — under-cap report byte-identical to the Inc-0 golden | **passed** |
| Snapshots | 29, unchanged |

So the edit cannot alter an emitted byte, and `AT-256` confirms that against a golden captured at
Inc-0 from the **shipped** producer in its own commit (C-12) rather than against the current code.

---

## §7 Definition-of-done checklist (hand-off §6)

| # | Requirement | Status |
|---|---|---|
| 1 | H-1…H-4 closed, each with an executed counterfactual reported **per arm** | ✅ 21/21 arms RED |
| 2 | Full gate suite green on a **settled** tree, provenance checked | ✅ 2514/2/3, exit 0, hashes + launch order recorded; **one** run, none discarded |
| 3 | Ledger reconciled against 2482 | ✅ on collection: `2508 − 0 + 11 = 2519`; the +21 explained as the lean-vs-full CI form |
| 4 | `04-validation.md` + `05-postmortem.md` + `06-docs/` | ✅ this file · ✅ written · ✅ **N/A declared in writing** with output neutrality verified |
| 5 | Backlog reconciled in the right lane, never duplicated | ✅ CC-1/harness-bytes → `BACKLOG-PROCESS.md`; reservation-floor hardening → `BACKLOG-CODE.md` |
| 6 | Independent `qa-reviewer` merge-gate pass returns clean | ⏳ next |
| 7 | `/dev-flow-sync` | ⏳ after 6 |
