# Inc 8 — E5 security review (implementation)

Batch 2026-11-01-batch-101, increment 8, branch `b101-inc8` at `e455a07`. Reviewer role: security-reviewer, independent of the authors. Read-only on the tree; this file is the only write.

## Verdict

**PASS-WITH-NOTES.** No HIGH and no MEDIUM finding. The E3 mitigations S-1 … S-7 are applied as ruled and pinned by tests that pass (10/10, see Probes). Four LOW/INFO notes remain; none blocks Inc 8. The pre-existing guard gap the integrator raised (SR-4) is **not widened** by Inc 8, is **LOW**, and belongs to **Inc 9** (D15-18 family), not to this increment.

## Scope reviewed

- `git diff main...HEAD -- s19_app`: `operations/crc.py`, `operations/crc_config.py`, `services/flow_execution_service.py`, `services/flow_model.py`.
- Tests that pin the guards: `tests/test_b101_flow_ext_copy.py` (9/15, 12/10, EXT.14/*, FLOW-CRC.9/1), `tests/test_b101_crc_model_and_reasons.py` (001.11/7, 001.11/8, 001.17/1-2).
- Unchanged code the new paths rely on: `workspace.place_into_workarea` / `copy_into_workarea` / `_guarded_destination`, `variant_execution_service._resolve_manifest_entry`, `crc_config.read_crc_config_text`, the summary sinks (`flow_report_service.py:442`, `flow_fused_report_service.py:214`, `flow_screens.py:2712-2715`, `:2862-2866`, `:3952`).
- Records: `01-requirements.md`, `E3-security.md`, `E3-rulings.md` (round 2, N-1 … N-4 binding), `E4-integration-notes.md` (SR-4).

## Rulings on the four questions

| # | Question | Ruling |
|---|---|---|
| 1 | External-step copy path handling | **Sound.** Destination: unchanged writer, `_guarded_destination` on the unresolved project folder (junction on the way refused). Source: a leaf link is refused (P6). Overwrite: never — a differing file claims the lowest free `_<N>` (`step.changes_1.json`, then `_2`), an identical file is reused (P5); the stale file keeps its bytes. `..`: a relative log/output that climbs above the project is refused by text (`flow_execution_service.py:1170`, `:1184`, `:1422`); rooted (`\x.json`) and other-drive (`D:x.json`) relatives fail closed (P2). NUL: `is_file()` is `False` on 3.11, so the block refuses it as missing, and the manifest guard refuses a NUL ref (P1, P4). Reserved names: `CON` / `aux` are never a file (refused as missing); on Windows 11 `nul.json` is an ordinary file and is copied as one (P4) — no device is opened. Residual: S8-1. |
| 2 | In-place reads named in the run summary | **Sound.** The rebind map is local to one `run_flow` call (`:259`), so no state crosses runs or lanes. The typed ref passes the guard first and the copy is re-guarded by name (`:1390-1420`); after a rebind an absolute ref and a junction-outside ref stay refused (P3, test 9/15). Every in-place read is appended to `in_place_reads` and named by the read suffix in the block summary, error summaries included (`finally`, N-4), before a trailing `unresolved` (N-2, probe 2). The accepted design risk (A-2: a bench output replaces a project file of the same name, first run included) is visible, not silent. Residuals: S8-3, S8-4. |
| 3 | Escaping of names into reports; raw names in records | **No injection.** Records carry raw values by design (SR-5: `FlowChangeRecord.change_doc_ref` / `a2l_ref`, `in_place_reads`, `ChainRunOutcome.inputs`); nothing opens them as paths. Every sink escapes: ledger and fused report through `md_safe` (Mode A), chain-set provenance through `md_safe(limit=120)` and `md_code` (`:2165-2179`), TUI through `safe_text` with `markup=False`, HTML through `_esc(_strip_ctl(...))`. Probe: a ref holding `|`, backticks, `<script>`, a newline, `#` and a link renders inert in the ledger cell; the newline is normalised. |
| 4 | `_resolve_manifest_entry` accepts a link back inside the project | **Confirmed, pre-existing, not widened, LOW, route to Inc 9.** See S8-2. |

## Findings

| Id | Tag | Severity | Where | Finding and scenario | Recommendation | Evidence state |
|---|---|---|---|---|---|---|
| S8-1 | design-gap | LOW | `flow_execution_service.py:1166-1192`, `:1422-1433` | R-FLOW-EXT.14 is a text check (`normpath`, no link followed). A relative output or log that passes through a junction inside the project pointing outside (`jout/x.json`) is not refused (P2) and the bytes are copied in from outside. Reach equals an absolute path (no escalation; leaf link refused, 256 MiB cap, human confirms), but the confirming human may read a relative path as "inside the project" — the S-3 premise. Inc 8 narrows the base behaviour (a relative output was read against the working directory). | Record as the accepted residual of R-FLOW-EXT.14, or close it in Inc 9 together with S8-2 (an `lstat` walk of the unresolved components). | executed (probe P2) |
| S8-2 | impl (pre-existing) | LOW | `variant_execution_service.py:913-916` vs docstring `:884-886` | Default mode resolves first, then walks the **resolved** path for reparse points; `resolve()` has already removed every junction and symlink, so the walk only sees reparse points `resolve()` does not follow (cloud placeholders). A ref `jin/step.changes.json`, where `jin` is a junction to the project itself, is accepted (P1) although the docstring says a link below the root is refused. **Not a containment escape:** a link whose target is outside resolves outside and is refused by the `escapes` check (P1 `jout`). **Inc 8 does not widen it:** the rebind runs after the guard and re-guards the copy; the read stays in the project and the suffix names the typed ref (P3: `jin/step.changes.json` → `step.changes_1.json`, in place). Real impact: a false contract and in-project aliasing. | Route to **Inc 9** (D15-18 family, link handling of flow paths) with a RED arm. Choose there: refuse by an `lstat` walk of the unresolved components (as manifest-keys mode does in `_walk_manifest_entry`), or correct the docstring — refusing may break a user who keeps a junction inside a project, so it needs a ruling. Does not block Inc 8. | executed (probes P1, P3) |
| S8-3 | impl | INFO | `flow_report_service.py:88`, `:442` | The ledger cell cap (240) applies to the whole summary. A summary carrying two suffixes with long names is clipped (probe: 331 characters → cell ends `in place of rrr…(truncated)`); the truncation marker is visible, and the copy name survived in the probe. For CHECK and CRC the summary is the only report place that names the copy. | None now. If long names become usual, give the read suffix its own report column or line. | executed (probe 2) |
| S8-4 | impl | INFO | `flow_execution_service.py:1222-1224` | The rebind key takes `Path(source_path).resolve().name`, computed after the copy. If the bench output leaf is swapped for a link between placement and this line, the key takes the link target's name, and a later ref naming that name reads the copy (named by the suffix; the bytes are the confirmed copy). Needs a local race on the bench folder. | Optional (backlog): key on `source_path.name`, the name placement copied. | planned |

## Checked, no finding

- CRC config read: the flow CRC block reads through `read_crc_config_text` (256 MiB cap, refused before reading; test FLOW-CRC.9/1). `<value>` is clipped to 64 characters plus `…` (`crc_config.py:103`, `_number_field`; test 001.11/7). `RecursionError` is caught (`parse_crc_config`; tests 001.17/1-2). `"[/]"` gives plain text (001.11/8).
- CRC model change (`crc.py:212`): one computation site; an image written by an older version now gives MISMATCH (visible); release note tracked (S-8).
- No secret, token, home path, account name, host or address in the diff or in the new test files' fixtures (grep).
- No new dependency, tool or integration.

## Probes run

All outside the repo, temp folder under the session's temp root, `LOCALAPPDATA` redirected, interpreter `s19env` (Python 3.11.15), `PYTHONPATH` = the worktree, `s19_app.__file__` printed first (the worktree's). No clipboard use; the real `%LOCALAPPDATA%\s19_app` was not touched. Junctions made with `_winapi.CreateJunction`.

| Probe | What | Result |
|---|---|---|
| P1 | `_resolve_manifest_entry` on `jin/…` (junction back in), `jout/…` (junction out), `sub/../…`, `../x`, NUL, `CON`, `nul.json`, `C:step…` | `jin` accepted (S8-2); `jout`, `../x`, NUL refused `MANIFEST-PATH-ESCAPE`; the rest resolve inside |
| P2 | `_climbs_above_project` on 10 relative spellings | `..`, `sub/../../`, `\x.json`, `D:x.json`, `..\PROJ\…` refused; `jout/x.json` accepted (S8-1) |
| P3 | `_resolve_block_ref` after a real `copy_into_workarea` | plain and `jin` refs read `step.changes_1.json` in place; absolute and `jout` refs stay refused |
| P4 | NUL and reserved names on the external-step checks; copy of a bench `nul.json` | all `is_file()` `False` before the copy; `nul.json` copies as a regular file |
| P5 | second copy, differing then identical bytes | `step.changes_2.json`, then reused; the stale file unchanged |
| P6 | symlink as the output | `WorkareaContainmentError` |
| probe 2 | read suffix through `_apply_block_read_suffixes` and the ledger escaper; N-2 placement; long names | escaped inert; `… in place of d.json unresolved`; clipped with a visible marker (S8-3) |
| pytest | `-k "9_15 or 12_10 or ext_14 or crc_9 or 001_11_7 or 001_11_8 or 001_17"` on the two new files, `--basetemp` in the temp folder, no cache | **10 passed** |

## Evidence checklist

- [x] Each finding has what, where, why and a recommendation — table above, S8-1 … S8-4.
- [x] Each finding has a severity — column 3; none HIGH or MEDIUM.
- [x] No secret values appear in this file — locations only.
- [x] The verdict is explicit — **PASS-WITH-NOTES**; no HIGH exists, so nothing is owed before Inc 8 closes.
- [x] No new tool or integration was added — n/a, none in the diff.
