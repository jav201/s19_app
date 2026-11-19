# Inc 10 — validation (E5)

**Verdict: PASS-WITH-NOTES.** No BLOCKER or MAJOR open. Reviewer X10 (claude-opus-5-5), one pass, code + security (`E5-review.md`). Base `439860c4`; reviewed `28a5c82f`; validated tree `f256579c` (= `28a5c82f` + the E5 bound test + records). Runner `<runner>` (HT-02 environment, HOME basename `<runner-home>`, `-p no:cacheprovider`, `timeout 300`, `-n` ≤ 2, `s19_app.__file__` the first line of every transcript; tree = `git archive`, laws = a clone of a bundle with `main` = `origin/main`). Host load 2 to 9 (other workers); nothing here is a timing result (HT-08). Transcripts: `evidence/e5/logs/` (sanitised: `~`, `<user>`, `<runner-home>`); scripts `evidence/e5/scripts/`.

## Runs

| Run | Result | Evidence |
|---|---|---|
| Inc 10 files: `g1_controls` + `g1_panel` | 51 passed | `logs/i10-g1.txt` |
| `g2_arms` + `g2_write` | 45 passed | `logs/i10-g2.txt` |
| `g3_engine` + `mu_survivors` + `s0_written_name` | 34 passed (33 + the E5 bound) | `logs/i10-g3.txt` |
| E5 bound test (F-X10-1): tree / MU24c copy / base | 1 passed / 1 failed in 0.10 s / 1 failed | `logs/bound-{tree,mut24c,base}.txt` |
| Shared: `test_b97_patch_editor` | 38 passed | `logs/sh-b97.txt` |
| Shared: `test_tui_patch_editor_v2` + `test_tui_patch_layout` | 61 passed | `logs/sh-v2-layout.txt` |
| Shared: `test_b100_active_variant -k tc_b100` / `-k "not tc_b100"` | 61 passed, 2 skipped / 10 passed, 1 skipped | `logs/sh-b100-tc.txt`, `sh-b100-rest.txt` |
| Shared: `test_b99_editor_image` + `test_b99_s0` + `test_changes_apply` | 54 passed, **1 failed = AT-B99-02** (expected) | `logs/sh-b99-apply.txt` |
| Shared: `test_b103_inc8_p_layout` + `test_tui_patch_chips` | 34 passed, **1 failed = AT-076a** (expected) | `logs/sh-inc8-layout-chips.txt` |
| Shared: `test_b100_load_question` (tree / base) | 54 passed, 4 failed / the same 4 failed | `logs/sh-test_b100_load_question.txt`, `base-…` — F-X10-4 |
| Shared: `test_b100_save_image` (tree / base) | 63 passed, 11 failed / 65 passed, 9 failed: the 9 identical; the 2 extra = TC-B100-59 ×2, load-sensitive (L-1) | `logs/sh-test_b100_save_image.txt`, `base-…`, `exact-b100-59*.txt`, `base-b100-59*.txt`, `diag59-*.txt` |
| Shared: `test_b100_workers` (tree / base) | timeout 300 at `-n 2` on both (not decidable in the HT-02 budget) | `logs/sh-test_b100_workers.txt`, `base-…` |
| Inc 10 retarget sites one by one (tree / base): TC-B100-14, -15, -58, -69; TC-B100-53 ×2 | 25 passed, 1 failed (TC-B100-58 mac attach, same on base) / same; 53: 2 passed / 2 passed | `logs/exact-b100-save-sites.txt`, `base-…`, `exact-b100-53{a,b}.txt`, `base-…` |
| Laws (clone): docs_canon, b101_doc_hygiene, b101_help_legend_docs, no_private_tokens, filename_markup_safety, report_markup_safety, id_registry, deps_seam_law, engine_unchanged, requirements_canon, suite_hygiene | 384 passed, **1 failed = R-DOC-CANON.4** (expected, P-026) | `logs/laws.txt` |
| Laws: `test_tui_directionb.py -k tc031` | 3 passed | `logs/laws-tc031.txt` |
| Laws on the E5 records (clone of `9eadcf22`): suite_hygiene, no_private_tokens, id_registry, filename_markup_safety, docs_canon | 85 passed. The first run on `c6331a9e` failed R-TST-070.2 (pytest truncated an account folder to `pytest-of-<user>…` in four of these transcripts, past the fetch redaction); fixed forward in `9eadcf22` | `logs/laws-final.txt` |
| Review probes P1–P3 | P1 0 differences; P2 control character kept (F-X10-3); P3 no mismatch | `probes/probe.txt` |

Expected base failures seen: AT-B99-02, AT-076a, R-DOC-CANON.4. **Also seen, outside the brief's list and identical on base:** F-X10-4 (b100 load_question 4, save_image 9, workers timeout). Load-sensitive and kept visible: L-1.

## Mutant score

E4 MU10 (`E4-mutants.md`): 59 mutants, 57 killed, 1 equivalent (MU26h), 1 timeout (MU24c). E5: MU24c is now killed in 0.10 s by the bound test (F-X10-1) → 58 killed + 1 equivalent.

## Review verdicts

`E5-review.md`: 0 BLOCKER, 0 MAJOR; F-X10-1 fixed (test); F-X10-2, F-X10-3, F-X10-4 MINOR → PENDING. Wording list (5 items) fixed in `4fc94f36`, no meaning changed. R-S19-S0HEADER-001.1/3 and R-S19-EMIT.11/1, /2 stay `conflict` (P-068; D8-27, D8-29).

## Captures and operator items — provisional, awaiting the operator's confirmation on the final page (P-059)

- Real Windows Terminal captures (HT-10), 10 PNG + sidecars at 118×54 and 220×60: dock idle, after Apply (O-1 line), Format chip `S19` / `Intel HEX`, numbered landing `firmware-patched_1.s19` — `E5-captures.md`. No capture contradicts a requirement.
- O-1 … O-6: the built options kept (A′ line; Width hidden with its place kept; Format chip; no key; no frame; only a final `.s19` / `.hex` replaced), each with its reason in `E5-review.md` § "Operator items (provisional, P-059)". Not approved.

## Not run

Full suite (batch end, DF-08); a mutant battery (only MU24c, on a copy); timing decisions (HT-08); a capture of the S0-from-name header with a numbered landing (case01 has S0 data; proven by tests only); `test_b100_workers.py` as a whole (times out at 300 s on base and tree).

## trace_check

```
$ python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-10/01-requirements.md --base 439860c4 --src s19_app
trace_check: 3 US, 44 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```
0 gaps (run from the repo root on the evidence commit; the first run, before the evidence was committed, listed 1 EVID gap: `evidence/e5/scripts/` not committed).
