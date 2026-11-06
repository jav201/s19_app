# Inc 14 — E5 security review (implementation, head 7d37efa)

**Verdict: split by merge unit.**
- **Inc 14 without the SECURITY.md group: OK to ship (security lens).** No HIGH, no open MEDIUM. S-2 … S-5 are implemented as ruled; the texts are accurate, carry no exploit detail, no unsafe instruction and no promise; no personal data or internal path was found.
- **SECURITY.md group: `BLOCK-UNTIL: E5-1`.** Private vulnerability reporting is still disabled (`{"enabled":false}`, 2026-11-05T23:42:44Z). Under ruling A-6 + S-1 and addendum N-2, the group is held out of the merge and re-checked at the batch end.

This review clears risk only. It is not merge, release or deploy authority.

## Scope reviewed

- `SECURITY.md` (new), `CHANGELOG.md` (new), `README.md`, `docs/user-guide/ch06`, `ch16`, `ch17`, `ch18`, `ch19`, `ch21`, `DOSSIER.md`, `s19_app/tui/window_help.py`, `s19_app/tui/legend.py` (the file set in `E4-impl-notes-{top,guide,code}.md`).
- The hold-out group in `tests/test_b101_help_legend_docs.py` (`:1219-1264`) and `test_r_doc_readme_4_2_linked_documents_exist` (`:1195-1199`).
- Records: `E3-security.md` (S-1 … S-8), `E3-rulings.md` (rounds 1, 2, N-1 … N-3), `E4-integration-notes.md`.
- **Method limit (stated, not hidden):** the brief allows only `gh api` reads on this PC, so no `git diff` was run. The branch `b101-inc14` is not on GitHub (`gh api repos/jav201/s19_app/compare/main...b101-inc14` → HTTP 404), so a remote diff was not possible either. Each file in scope was read or scanned **whole** at its current text. That is a superset of the diff. Whether a line is new or pre-existing is taken from the E4 implementer notes and from E3, not from git.

## gh api result (E5 evidence, R-DOC-SECURITY.1/2)

| Field | Value |
|---|---|
| Date (UTC) | 2026-11-05T23:42:44Z |
| Command | `gh api repos/jav201/s19_app/private-vulnerability-reporting` |
| Exit code | 0 |
| Output | `{"enabled":false}` |
| Transcript | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/gh-pvr.txt` |
| Case R-DOC-SECURITY.1/2 | `failed` (the setting is off) |

## Rulings implemented (S-2 … S-5)

| Item | Ruling | Shipped text | State |
|---|---|---|---|
| S-2 | CHANGELOG `### Flows` gives the remedy for a climbing relative log or output path, with no description of the escape | `CHANGELOG.md:54`: "…climbs above the project folder now stops the flow with `external step refused`; give an absolute path for a file outside the project." | `executed`, verified |
| S-3 | CHANGELOG `### Reports`: no partial or orphan report, control and direction-override characters shown visibly, a safe-to-delete `.part` file, and no word on why the staging name is random | `:42`, `:44`, `:46`. A scan for `random` finds none. | `executed`, verified |
| S-4 | SECURITY scope lists `project.json`, flow sets, report filters, CRC Designer templates and pasted text | `SECURITY.md:21` | `executed`, verified |
| S-5 | SECURITY names the two processes it starts on purpose and says the external-step command is never run. README tells the reader to read the command before running it and to import flows only from trusted sources | `SECURITY.md:21`; `README.md:190` | `executed`, verified |
| S-6 | `1.0.x` only; ships with 1.0.0 | `SECURITY.md:7-8` | as ruled (see E5-3) |
| A-6 / S-1 | No public-issue fallback, no e-mail address, no promise of a response time | `SECURITY.md:10-17`: none of these appears | `executed`, verified |

## Accuracy of the claims

The SECURITY.md claims were checked against `s19_app/` at this head.
- **No network.** No `socket`, `urllib`, `requests`, `http.client` or `webbrowser` use appears. `markdown_safety.py:47` is a docstring.
- **Two processes only.** `subprocess` runs only in `services/folder_open_service.py:194` (the file manager) and `os_clipboard_input.py:359` and `:522` (the clipboard command). No `os.system`, `startfile`, `exec` or `spawn` appears.
- **Wording.** The "Examples of a vulnerability" sentence names classes only (write outside the work area, run a command, paint escape sequences or markup, unbounded memory or time). It holds no exploit detail.
- **No disabled channel claimed as enabled.** `SECURITY.md:12` says where to click. It does not say the setting is on. The record of the setting is the E5-1 evidence.
- **CHANGELOG.** The CRC values match E3's independent recomputation. The CRC section does not present CRC as an authenticity control.

## Personal data and internal paths

A scan of every file in scope looked for home paths, the operator's names, hostnames, IPv4 addresses, e-mail addresses, `My Drive`, `~/`, PKI and signing terms, tokens, keys and passwords. **No hit in any Inc 14 text.**

There are three expected matches:
- `jav201` in `README.md:59` (`git clone`) is the public repository slug. It was there before Inc 14 (E3 S-7).
- A demo folder, `s19demo` under the shared Windows Public profile, appears in `ch17-flow-builder.md:185-197` and `DOSSIER.md:14`. It is the shared Public folder used for the demo, not a personal home path. These lines lie outside the passages Inc 14 rewrote (`ch17` /4 and /5 sit at `:59-66` and `:175-182`).
- `token` matches in `window_help.py` and `legend.py` are identifiers for key-bar and style tokens.

## Hold-out group: no dangling link

The search excluded `.dev-flow/`. It found `SECURITY.md` referenced only in:
- `README.md:429`, the `## Documentation` row;
- the three `test_r_doc_security_*` tests;
- the test module docstring (`:7`, `:17-18`).

It found no reference in `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl`, `docs/`, `CHANGELOG.md` or `s19_app/`.

The group is held out as N-2 defines it: the file, its three tests (`:1224`, `:1240`, `:1261`) and the README row `:429`. After that:
- `test_r_doc_readme_4_2_linked_documents_exist` still passes, because every remaining README link target exists and `CHANGELOG.md` stays;
- no README link points at a missing file;
- no registry row names a removed test;
- the TC-607 file count does not change, because the tests sit in a file that stays.

**Confirmed: no dangling link**, provided the README row goes out with the file. See E5-2 for the one stale docstring sentence.

## Findings

| id | tag | severity | where | finding | recommendation |
|---|---|---|---|---|---|
| E5-1 | design-gap | MEDIUM | `SECURITY.md:12`; R-DOC-SECURITY.1/2 | **The reporting channel the policy names is still closed.** `{"enabled":false}` at 2026-11-05T23:42:44Z. A published policy that points to a missing **Report a vulnerability** button leaves a reporter with no private route (E3 S-1). | Hold out the N-2 group at merge: `SECURITY.md`, the three `test_r_doc_security_*` tests and `README.md:429`. Re-run the `gh api` read at the batch end. The group merges only on `{"enabled":true}`, with a new dated transcript. Turning the setting on is the operator's action. |
| E5-2 | impl | INFO | `tests/test_b101_help_legend_docs.py:7` | If the group is held out, the module docstring still lists `SECURITY.md` among the documents the file checks. It is a text sentence, not a link, and no test reads it. | When the hold-out is applied, cut `SECURITY.md, ` from line 7 and keep the N-2 banner text at `:17-18`. Optional. |
| E5-3 | design-gap | INFO | `SECURITY.md:7-8` | Carried from S-6: the table supports only `1.0.x`, while the tree is at `1.0.0rc1`. The table is correct only once 1.0.0 is tagged. | None if the file ships with the 1.0.0 release, as ruled. At the batch-end re-check, confirm that `version.py` reads `1.0.0` before `SECURITY.md` merges. |
| E5-4 | impl | INFO | `E3-security.md:28`, `E4-integration-notes.md:65` | The records name the transcript `evidence/inc14/gh-pvr.txt`. It was saved at `evidence/inc-14/gh-pvr.txt`, beside the other Inc 14 transcripts, as the brief directs. | Fix the two citations at the E5 records pass. |

No HIGH. No LOW. No finding against S-2 … S-5.

## Evidence states

| Item | State |
|---|---|
| `gh api` private-vulnerability-reporting read | `executed` (`enabled:false`) |
| R-DOC-SECURITY.1/2 (channel open) | `failed` as of 2026-11-05T23:42:44Z |
| S-2, S-3, S-4, S-5 mitigations in shipped text | `executed`, verified by this review |
| S-1 / A-6 hold-out of the SECURITY.md group | `planned` (the orchestrator applies it at merge) |
| Personal-data and internal-path scan | `executed` (whole files, not `git diff`; see the method limit) |
| Dangling-link analysis of the hold-out | `executed` (by reading; the tests were not run on this PC, per the brief) |
| Tests | `n/a — E5 security review is read-only; runs belong to the LAN host` |

## Checklist

- [x] Each finding has what, where, why and a recommendation: the table above.
- [x] Each finding has a severity: the table above.
- [x] No secret values in this report: none were read or quoted.
- [x] The verdict is explicit: OK for Inc 14 without the SECURITY.md group; `BLOCK-UNTIL: E5-1` for the group. No HIGH.
- [x] New tool or integration: none. Private vulnerability reporting is a repository setting with an incoming-only blast radius (E3).
