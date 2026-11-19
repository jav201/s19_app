# Privacy forward fix — 2026-11-19

Written 2026-11-19 09:07 CSTM (from `date`). Base: `main` `f44e8bc4`. Branch: `privacy-forward-fix`.

## Why
An independent privacy review of the public remote (review R3, 2026-11-19, kept outside the repo) found personal and host-identifying data on the tip of `main`, invisible to both privacy laws:
- a raw agent session transcript with identity data, an SSH key comment and fingerprint, and lab account guesses against the test runner;
- three evidence redaction helpers that spelled the lab accounts and a LAN address as split string literals;
- truncated account names (`pytest-of-…`) in committed full-suite logs and JUnit files;
- the operator's full name in three older records, identity fields in a saved design mock, and the operator's first name in two new batch-103 records.

## Operator decision
2026-11-19, in the review session, the operator chose: «Corregir hacia adelante (Recomendado)» — a forward commit on `main`, deletion of the stale public branches, history left intact (same policy as the 2026-11-13 forward redaction).

## What changed (counts only; no value is written here)
| Change | Files |
|---|---|
| Raw transcript `inc-2/evidence-e4/kimi-e4-tests-2b.txt` replaced by a short factual note (path kept; records cite it) | 1 |
| Redaction helpers `inc-3/5/6/evidence-e5/redact_inc*_evidence.py` deleted (one-shot tools; their output is already committed) | 3 |
| Truncated account names → `pytest-of-<user>` / `<user>…` (165 replacements) | 17 |
| `stored_sha256` refreshed for every redacted file listed in a `MANIFEST.tsv` (`original_sha256` unchanged) | 6 |
| Full name → `<operator>` in batch-88 records | 3 |
| First name → "the operator" in `inc-9/E4-fixes-fx9f.md`, `inc-9/E5-review.md` | 2 |
| Identity fields of `2026-05-20-batch-02/design-input/Hex-Lab-mock.html` → placeholders | 1 |
| Account spelled in a docstring example of `tests/test_no_private_tokens.py` → `x<token>` | 1 |

## Verification
- Static re-scan of every tracked text file after the change: redaction-token column 0, surname 0, split-literal tokens 0, account-prefix `pytest-of-` 0, personal e-mail 0.
- Every `MANIFEST.tsv` row that points at a redacted file matches its new stored bytes (0 mismatches).
- The pre-push scan `pp02_scan.py` was found unable to fail (it used whole `token<TAB>placeholder` lines as needles). Fixed outside the repo to use the token column, with a planted self-check; negative control on the unpushed `a2l-load-performance` diff now reports 257 needle hits (was 0).
- Scoped tests on a lab host: `tests/test_no_private_tokens.py` and `tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` / `::test_r_tst_070_3_redaction_gate_names_each_leak_form`. R-TST-070.2 is expected to stay red after this fix for non-privacy reasons (unaccepted placeholder spellings, GitHub runner identities, prose false positives), tracked separately.

## Not changed
- History. The data above remains reachable by commit SHA; removing it needs a history rewrite, which the operator did not choose.
- The bare first name in about 40 records older than 2026-10-11 (s19 was excluded from that scrub).
- Commit metadata (author names and e-mails on older commits).

## Rule
Raw agent session transcripts are never committed under `.dev-flow/`.
