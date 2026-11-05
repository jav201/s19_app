# Inc 14 — E3 security review (design, code-free)

**Verdict: PASS-WITH-NOTES.** No HIGH finding. One MEDIUM (S-1: the private reporting channel that `SECURITY.md` names does not exist yet, and the text has no fallback) is a merge condition, not a design defect: the D-1 ruling already defers the check to E5. The proposed texts hold no secret, personal name, home path, host, IP address, e-mail address, or PKI / signing content. No proposed text tells a user to disable a check, follow an external link, or run a command the project did not author. The CRC release note is accurate and carries no exploit detail. This review clears design risk only. It is not merge or release authority.

## Scope reviewed

- `codewire/graph-inc14.md`: `[I/O: SECURITY.md]`, `[I/O: CHANGELOG.md]`, `[I/O: README.md]` blocks (1)–(15), `[I/O: docs/user-guide passages]` /1–/11, `[I/O: DOSSIER.md §5]`.
- `01-requirements.md`: Help copy I14, Legend copy I14, R-DOC-SECURITY.*, R-DOC-RELNOTE.*.
- `E1-rulings.md`: D-1, D-2 and the orchestrator rulings. `02-test-cases.md`: the R-DOC-SECURITY and R-DOC-RELNOTE rows.
- `../inc-8/release-note-crc.md`; `../inc-7/E5-security.md` (C-1 random staging names); `../inc-8/E3-rulings.md` S-3 … S-6 (external-step guards); `../inc-7/E3-rulings.md` S-1, S-2.
- Code checks for the claims in the scope statement (read at `ddbc8e0`; nothing imported):
  - Network: `grep` of `s19_app/` for `socket`, `urllib`, `http`, `requests`, `webbrowser`, `urlopen` imports. No hit. The only `http://` strings are in docstrings.
  - Processes: `subprocess` appears only in `services/folder_open_service.py:194`, where it opens the OS file manager on a folder, and in `os_clipboard_input.py:359`, `:522`, which run a fixed PowerShell clipboard command. `flow_execution_service.py` starts no process; an external step's command is shown, never run (`:1148-1155`; the guide says the same at `ch17-flow-builder.md:160`).
  - Writes: the patched image is written through `save_patched_image(…, workarea_root=…)` (`app.py:12061`).
- CRC values. I recomputed them with a standalone Rocksoft-model script that does not import `s19_app`; it lives in the scratchpad, not the repository. Over `123456789`, poly `0x04C11DB7`, refin/refout true, xorout `0xFFFFFFFF`:
  - Check value with init `0xFFFFFFFF`: `0xCBF43926`.
  - Init `0x12345678` gives `0x0F8B7431`.
  - `reflect(0x12345678)` = `0x1E6A2C48`, which gives `0x18026B2A`.
  - `reflect(0x0FF00FF0)` = `0x0FF00FF0` (the note's bit-symmetric example).

  All four match the release note.
- No test, probe or `s19_app` import was run on this PC or on the LAN host. This is a document-only design review: every claim above was read, or computed without the package.

## Findings

| id | severity | row / node | finding | proposed fix |
|---|---|---|---|---|
| S-1 | MEDIUM | R-DOC-SECURITY.1, `[I/O: SECURITY.md]` | **The named channel is not open, and the text gives no fallback.** The text tells a reporter to open the Security tab and choose **Report a vulnerability**. While private vulnerability reporting is disabled (the D-1 probe returned `{"enabled":false}`), that button does not exist. A reporter who cannot find it has no private route and may do what US-SEC-1 exists to prevent: open a public issue with the details. The text does not claim the setting is enabled, so it complies with D-1. The risk lies in the order of events: `SECURITY.md` would be live on a public default branch before the channel is. | Choose one. (a) Preferred: the merge of `SECURITY.md` to `main` waits for the E5 evidence `evidence/inc14/gh-pvr.txt` showing `{"enabled":true}` (the operator's action). Record this in the E5 gate as a merge precondition, not only as a `failed` row. (b) If the merge cannot wait, add one sentence: "If the Security tab shows no **Report a vulnerability** button, open a public issue titled `Security contact request` with no details of the vulnerability, and a private channel will be arranged." This adds no e-mail address and no time promise. |
| S-2 | LOW | R-DOC-RELNOTE.*, `[I/O: CHANGELOG.md]` `### Flows` | **One user-visible guard of Inc 8 is missing from the 1.0.0 notes.** Under R-FLOW-EXT.14 (Inc 8 S-3), a confirmed external step whose *relative* log or output path climbs above the project folder (`..`) now stops the flow with `external step refused`. In 1.0.0rc1 the same flow ran. That is a change in what the app does with a saved flow, which is the kind of change the changelog says it lists. R-FLOW-CRC.9 (256 MiB read limit) and R-CRC-CONFIG-001.17 (nesting too deep) refuse only pathological files and need no note. | Add one bullet under `### Flows`: "A confirmed external step whose relative log or output path climbs above the project folder now stops the flow with `external step refused`; give an absolute path for a file outside the project." The bullet gives the remedy only. It does not describe the escape it prevents. New row R-DOC-RELNOTE.7, or fold it into .4. |
| S-3 | LOW | `[I/O: CHANGELOG.md]` `### Reports` | **Two Inc 7 changes to written reports are not stated.** (a) Inc 7 S-2: control and direction-override characters in names and paths are now written as visible replacements in both the `.md` and `.html` report files. A name that holds them reads differently from rc1. (b) Inc 7 C-1: reports are written through a staging file `<name>.<16 hex>.part` that is then renamed. An interrupted write can leave that file beside the report, and the app never removes it. | (a) Extend bullet (c): "…and control or direction-override characters in a name or path are written as visible replacements." (b) Optional: "An interrupted report write can leave a `<name>.<hex>.part` file in the reports folder; it is safe to delete." Do **not** state why the staging name is random. That would describe the attack it closes. |
| S-4 | LOW | `[I/O: SECURITY.md]` `## Scope` | **The scope's list of inputs leaves out the main path-bearing input.** It lists S19, HEX, A2L, MAC and the change-set, check, CRC and flow JSON files. It omits: <ul><li>`project.json` (its entries are paths: the containment surface of D15-18 and the `_resolve_manifest_entry` guards);</li><li>flow sets (`flowsets/*.json`);</li><li>filter files;</li><li>CRC Designer templates;</li><li>text pasted into the Patch Editor.</li></ul> A reporter may then read a crafted manifest as out of scope. | Change the list to "S19, Intel HEX, A2L, MAC, project manifests (`project.json`), and the change-set, check, CRC config, CRC template, flow, flow set and filter files, and text pasted into the app". |
| S-5 | LOW | `[I/O: SECURITY.md]` `## Scope`; README block (8) | **The by-design processes and the external-step trust model are not stated.** The app starts two processes on purpose: the OS file manager (`o`, the Open … buttons) and the OS clipboard command. An external step's command is text from the flow file that a person is asked to run; the app never runs it. Without these facts, a reporter may file the file manager as "runs a command". A user may also paste a command from a flow or flow set someone sent them without reading it. Neither README block (7) nor block (8) says the command comes from the flow file. | In SECURITY.md `## Scope`, add: "Apart from opening a folder in the file manager and using the system clipboard, the app starts no process; it never runs an external step's command, which a person runs outside the app." In README block (8), add: "The command or instruction of an external step is text from the flow file: read it before you run it, and import flows only from sources you trust." |
| S-6 | INFO | R-DOC-SECURITY.2 | **No released version is supported until 1.0.0 is tagged.** The table supports `1.0.x` and excludes the release candidates, while the tree is at `1.0.0rc1` (`version.py`, `pyproject.toml`; tag `v1.0.0-rc1`). That is correct only if `SECURITY.md` ships with the 1.0.0 release. | None if Inc 14 lands in the 1.0.0 release. Otherwise, state that at merge. |
| S-7 | INFO | records only | The GitHub owner handle appears in `gh api repos/<owner>/s19_app/...` in `E1-rulings.md:81`, `02-test-cases.md:68` and `graph-inc14.md:243`. It is the public repository slug, already in `README.md:59` (`git clone`). It is not a personal name and appears in no product text. | None. |
| S-8 | INFO | positive | The CRC note (copied verbatim, without its process line) contains the parameter example, the bit-symmetry rule and the remedy only. None of these is exploit detail, and CRC is not presented as an authenticity control. The `### Flows` bullet and guide /5 and /6 describe rebinding by its visible summary suffix only. No proposed text asks a user to disable a check, skip a refusal, or run a command; the existing ch18 step 4 command is project-authored demo text and is unchanged here. The `pip show s19tool` instruction reads only the local install; README installs from `git clone` + `pip install -e .`, so no PyPI name is relied on. | None. |

## Evidence states

| Item | State |
|---|---|
| S-1 … S-8 found by reading the records, the code and the `grep` results above | `executed` |
| CRC example values recomputed without `s19_app` | `executed` |
| Mitigations S-1 (a) or (b), S-2, S-3, S-4, S-5 | `planned` |
| R-DOC-SECURITY.1/2 (channel open) | `not-run` (needs the operator's setting; evidence at E5) |
| Tests and probes on the LAN host | `n/a — document-only increment; no code path, no product function or test changes at E3` |

## Checklist

- [x] Each finding has what, where, why and fix: the table above.
- [x] Each finding has a severity: the table above.
- [x] No secret values in this report: none were read or quoted.
- [x] The verdict is explicit: PASS-WITH-NOTES. No HIGH finding. S-1 is a merge precondition under D-1.
- [x] New tool or integration: none. GitHub private vulnerability reporting is a repository setting the operator turns on. Its blast radius is incoming reports only.
