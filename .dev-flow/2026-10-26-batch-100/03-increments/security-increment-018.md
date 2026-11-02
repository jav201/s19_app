# Security review — increment 018 (batch-100 Inc 9b, the unified Load dialog), E5 (SEC9b-)

**Verdict: PASS-WITH-NOTES** — 0 HIGH · 0 MAJOR · 2 MINOR · 1 NIT.

I verified each mitigation E3 settled against the code, not the design. The two E3 MAJOR findings are applied and verified:
- **S9b-1** (the whole-stack guard against `ctrl+p`): `executed` and `approved`.
- **S9b-2** (link-safe preview; `project.json` checked before any read): `executed` and `approved`.

The open rows below are not trust-boundary breaks:
- **SEC9b-1:** the app crashes on one more input class that R-5 says cannot occur. It was pre-existing on 9a, but 9b moves it into the dialog.
- **SEC9b-2:** the `project.json` gate is narrower than the codebase's own regular-file test, and narrower than the S9b-2 proposal.
- **SEC9b-3:** the same narrowing in the listing (NIT).

This clearance is not ship authority and not the operator's authorization.

Scope: `git diff 8947666..741cc07 -- s19_app tests` on `<HOME>/Github/s19_app-b100-inc9b` (branch `b100-inc9b`, commit `741cc07`). Source files: `s19_app/tui/app.py`, `screens.py`, `styles.tcss`, `__init__.py`. Design read: `inc-9b/E3-security.md`, `E3-rulings.md` (round-3 addenda), `E4-integration-notes.md` (SR-1 … SR-7), `E4-app-notes.md`, `codewire/proto-9b-app.md`, `E1-requirements-draft.md`.

Environment: Python 3.11.15, Textual 8.2.8 (`s19env`), on Windows. Probes are under the session scratchpad (`rev9b-security/`), with `LOCALAPPDATA` pointed at the scratchpad. The tree was not edited.

## Findings

| Id | Sev | Tag | Where | Defect | Evidence | Fix |
|---|---|---|---|---|---|---|
| SEC9b-1 | MINOR | design-gap | `app.py:7652` (`_load_dialog_verdict` calls `_typed_load_route` with no catch; R-5); `app.py:13367-13371` (the relative branch calls `resolve_input_path`); `workspace.py:2024-2028` (`expanduser()`, `(base_dir / candidate).resolve()`); `screens.py:325` (`#load_path` has `restrict=` but no `max_length`) | **Failure:** the user pastes one line longer than about 32 000 characters into `#load_path` (for example a one-line base64 or minified-JSON blob from the clipboard) and presses Enter. `resolve_input_path` raises `ValueError: stat: path too long for Windows`. The exception escapes `_typed_load_route` and the verdict, inside the dialog's key handler, so the app exits (return code 1) and unsaved patch edits are lost.<br>**POSIX variant:** typed `~nosuchuser/a.s19`. `Path.expanduser()` raises `RuntimeError("Could not determine home directory.")`, with the same crash. On Windows this arm returns `None`.<br>**Why it matters:** this is the same class as S9b-4 (NUL). R-5 rests on "`_typed_load_route` never raises", and `restrict=` closed only the control-character input. On 9a the same crash happened after the dialog closed, so the bug is pre-existing; 9b moved it into the dialog. | **Executed** (`probe_e2e.py`): `inp.replace("a/"*20000, 0, 0)`, the same call `OsClipboardInput.action_paste` makes, then `enter` → `ValueError: stat: path too long for Windows`, `app.is_running False`, `return_code 1`, dialog still on the stack.<br>**Executed** (`probe_resolve.py`, `probe_resolve2.py`): a 40 000-character base64 line, a single 40 000-character component and a 33 000-character relative path → `RAISES ValueError`. Absolute paths of the same length → `None`.<br>**By reading:** the POSIX `~user` arm, from the Python 3.11 `pathlib.Path.expanduser` source. | Remove the input class, as for S9b-4: give `#load_path` a `max_length` (for example 4096). `Input.replace` enforces it for typing and paste, and the redirect appends one printable character at a time. Also map `(ValueError, RuntimeError)` from `resolve_input_path` inside `_typed_load_route` to `("refuse", "not found")`, so R-5 is true for every input, including the POSIX `~user` arm. Add a TC-B100-63 arm: a 40 000-character paste, then Enter → `#load_reason` shows a refusal and the app keeps running. |
| SEC9b-2 | MINOR | impl | `app.py:7711-7724` (preview gate) and `app.py:12194-12218` (`_handle_load_project` gate) test `S_ISREG(lstat)` only; compare `app.py:12663-12667` (`_folder_holds_project`) and `app.py:12773` (`_a2l_admission`), which both add `not _is_reparse_point` | The two S9b-2 `project.json` gates do not apply the reparse-point half of the codebase's regular-file test. E3 S9b-2 proposed exactly that test ("`S_ISREG` and not `_is_reparse_point`"), and the ruling says "the existing lstat regular-file check".<br>**Mechanism:** on Windows, `os.lstat` follows reparse points that are not name surrogates (for example cloud-file placeholders) and reports `S_ISREG`. `_is_reparse_point` still sees `FILE_ATTRIBUTE_REPARSE_POINT`.<br>**Failure:** a project folder holds `a.s19` and a `project.json` that is a dehydrated cloud-files placeholder (a work area under a Files-On-Demand sync folder). Highlighting the project calls `read_project_manifest` → `open()` → hydration over the network on the event loop, so the dialog freezes until the download ends or fails. Enter does the same.<br>**Inconsistency:** the same file is "no manifest" to `_folder_holds_project`, and an A2L of the same kind is refused by `_a2l_admission`. Three tests of one file disagree. | By reading. I could not create a placeholder on this host, so the scenario is not executed.<br>Executed control (`probe_e2e.py`): a symlinked `project.json` → preview `could not be read`, 0 opens of the target; load → 1 status line `could not be read`. So the symlink and FIFO arms hold; only the non-symlink reparse arm is open. | In both gates use `stat.S_ISREG(st.st_mode) and not _is_reparse_point(manifest_path)` (the `_folder_holds_project` test), ideally as one helper used by all three sites. No new token is needed: the refusal stays `could not be read`. |
| SEC9b-3 | NIT | design-gap | `app.py:12721-12723` (`_list_project_files`: `entry.is_file(follow_symlinks=False)` only); the design node in `proto-9b-app.md` prescribes exactly this test | On Windows, `DirEntry.is_file(follow_symlinks=False)` is `False` only for `IO_REPARSE_TAG_SYMLINK`. Other reparse files are listed as data files: a WSL `LX_SYMLINK` (a link, which LLR-173.4n says is "neither listed nor installed"), a cloud placeholder, an AF_UNIX socket file. `list_workarea_files` and `_a2l_admission` exclude them.<br>**Failure:** project `P` holds `b.s19`, a WSL-created symlink. The preview lists and marks `b.s19`. At Enter the install tries to open it: Win32 cannot follow an LX symlink, so the open fails, and a placeholder hydrates. The preview opens no data file, so the cost lands only at Enter. | By reading (CPython's Windows `DirEntry` derives `S_IFLNK` only from the symlink tag). | Add `and not (entry.stat(follow_symlinks=False).st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)` on Windows (no extra syscall; the attributes come from the directory listing), or call `_is_reparse_point(item)`. Correct the node text at close. |

## Re-verification of the E3 mitigations (the gate I owed)

| E3 item | State | Code evidence |
|---|---|---|
| S9b-1, the whole-stack guard against `ctrl+p` | `executed`, `approved` | `app.py:8423-8426`: `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, LoadDialog) for s in self.screen_stack)` → `False`. `_LOAD_DIALOG_INERT_ACTIONS` (`app.py:317-319`) equals the 4 app `priority=True` bindings (`app.py:2155-2158`; grep shows no other `priority=True` app binding). The app defines no `COMMANDS` provider and no `get_system_commands`, so the palette exposes no app action. Ran `test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open`: passed (`ctrl+p`, then `ctrl+s` and `ctrl+l` → no Save, 1 dialog; B91 no over-reach). |
| S9b-2, link-safe preview and the `project.json` gate | `executed`, `approved` (symlink and FIFO arms; see SEC9b-2 for the reparse arm) | `_list_project_files` (`app.py:12721`) is one `os.scandir` with `is_file(follow_symlinks=False)`, shared by the preview (`:7709`), the install (`:12116`) and `_folder_holds_project` (`:12670`). The `project.json` lstat gate runs before `read_project_manifest` in the preview (`:7711-7724`) and before the reset in the install (`:12194-12218`). An absent file is not a refusal (R3-1(a)). When the gate refuses, the preview returns only the token line, so 0 marks (R3-1(b)). Executed `probe_e2e.py` (Windows file symlinks available): linked `project.json` → preview `could not be read`, 0 opens of the target; `_list_project_files` → `['a.s19']` (linked `b.s19` skipped); load → `could not be read`. Ran `test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused` and `…_linked_file_in_a_project_is_neither_listed_nor_installed`: 2 passed, 0 skipped. |
| S9b-4, `restrict=` on `#load_path` | `executed`, `approved` (for its stated class) | `screens.py:325` `restrict=r"[^\x00-\x1f\x7f]*"`, which matches the ruling (C0 + DEL; C1 was not ruled in). Paste goes through `Input.replace` (`os_clipboard_input.py:511`), which applies `restrict`. The list-to-field redirect appends only `event.is_printable` characters. Ran `test_tc_b100_63_pasted_nul_is_not_inserted`: passed. The length class is SEC9b-1. |
| S9b-5, scrubbed status lines | `executed`, `approved` | `Project not found:` (`:12074`) and `A2L loaded:` (`:13780`) go through `painted_names`. |
| S9b-6, the A2L pick keeps the copy | `executed`, `approved` | `_load_workarea_file` (`:13968-13973`): an A2L goes to `load_a2l_from_path` → `copy_into_workarea` (cap and reparse re-check kept); data goes to `load_selected_file` (the 9a arm). |
| S9b-7 / R3-2, a folder named like a file | `executed`, `approved` | `_typed_load_route` `:13425-13436`: a data or A2L kind only when the last `lstat` is `S_ISREG`; otherwise not-a-dir → `not a supported file`, and a one-component dir → the project route. Executed `probe_e2e.py` verdicts: unlisted `<W>\ab.s19` dir → `not a project`; listed `<W>\cd.s19` → `None` (loads the project); `<W>\P\x.s19` dir and `<W>\temp\y.a2l` dir → `not a project`; outside dir `x.s19` → `outside the work area`; relative dir `rel_dir.s19` → `not a supported file`. No arm reaches `load_from_path` with a folder, so the S9b-7 absolute-path status line cannot be painted. Ran `test_tc_b100_63_folder_named_like_a_data_file`: passed. |
| S9b-8, preview nowrap | `executed`, `approved` | `styles.tcss:1827` `#load_preview Static { text-wrap: nowrap; text-overflow: ellipsis; }` (SR-1). `painted_names` removes Cc/Zl/Zp, so no name carries a line break. Ran `test_tc_b100_64_preview_line_never_wraps`: passed. |
| R3-4 / SR-2, no early stop | accepted cost, `n/a — orchestrator ruling SR-2` | `_folder_holds_project` lists through `_list_project_files`; the listing is metadata only and follows no link. This is cost, not a security defect. |

## Checked and fine

**Painted text: each string from disk is scrubbed once**
- Rows (`app.py:7585`, `:7596`, `:7614`): project names, work-area names and the recent file name go through `painted_names`.
- The recent `kind` comes from the store, which checks it against `recent_kind`.
- The store problem paints the constant word and step (`_RECENT_PROBLEM_STEPS`); no store path is painted.
- Preview:
  - recent: the full recorded path through `painted_names(clip=len)`. This is the user's own source path, by design (LLR-173.4i, Q4); `kind` is computed from the suffix.
  - work area: every name and `current_project` through `painted_names`.
  - project: variant, MAC and A2L names through `painted_names`; the state words are constants.
- `#load_reason` paints only `_TYPED_REFUSAL_TOKENS` values or `LOAD_NOTHING_SELECTED`. All 6 reasons `_typed_load_route` returns are keys, so no `KeyError`.
- `OptionList(markup=False)`, and the preview is a `Text` in a `Static(markup=False)`.
- Where a status line wraps `painted_names` in `safe_text(...).plain`, both steps only remove characters, so the second pass changes nothing (no double-escape artefact).

**No absolute per-user path is painted**
- No store location is painted (rows, problems, record failures go to the log only).
- The dialog refusals are tokens.
- `_handle_load_project` paints names only.
- The S9b-7 route that painted the absolute work-area path is closed (above).
- Pre-existing raw `{exc}` and `{path}` status lines in `load_from_path` / `load_a2l_from_path` (`:13622`, `:13640`, `:13690`, `:13726`) carry only paths the user typed or recorded. They stay on the Inc 12a sweep backlog (S9b-5).

**The link-safe listing never follows a link (symlink and junction)**
- `_list_project_files`: `scandir` + `is_file(follow_symlinks=False)` (reparse caveat in SEC9b-3).
- `_folder_holds_project`: lstat + `_is_reparse_point` on `project.json`, then that listing.
- `_a2l_admission`: lstat, `S_ISREG`, `_is_reparse_point`, cap (the 9a rule verbatim, A9b-R3-2 strings).
- `list_projects`: `_project_folder_refusal` (lstat) before `is_dir()`.
- `_handle_load_project` re-runs the folder refusal before any listing.

**No FIFO is opened on the 9b routes**
- `project.json` FIFO → the preview and install gates refuse it.
- A FIFO child is not `is_file` → skipped.
- A FIFO typed inside W → `not a supported file`.
- The FIFO arm of TC-B100-64 runs off Windows; on this host the symlink arm ran.

**The recent-sources record condition (LLR-172.1n)**
- `app.py:13656-13665` and `:13732-13741`: `via_fallback = normalized.is_absolute() and not typed.is_absolute()`. It is pure, and the same in both loaders.
- `resolve_input_path` returns the typed candidate unchanged when it exists, so "relative typed and resolved absolute" is exactly "found through the fallback".
- A typed `~` path is absolute after `expanduser` on both sides, so it is not treated as a fallback.
- A drive-relative `C:x.s19` found as typed stays relative and is recorded lexically; found through the fallback, it is not recorded.
- Ran `test_tc_b100_34_source_found_through_a_junction_fallback_is_not_recorded` and `…_a2l_found_only_through_the_fallback_is_not_recorded`: passed.

**Failure paths keep the app running (except SEC9b-1)**
- Rows: `list_projects` `OSError` is caught (`:7573`); `list_workarea_files` and `read_recent_sources` never raise.
- Preview: every filesystem step sits inside `except OSError`; `PermissionError` on the `project.json` lstat gives `could not be read` (G-B deviation 5).
- `_handle_load_project`: `OSError` from `list_projects`, `_list_project_files` and the `project.json` lstat paints 1 status line before the reset (F-12, B99).
- `_folder_holds_project` never raises.
- `_close` and `action_load` return early on `_dismissed`, so 2 Enters give 1 dismiss.

**Other checks**
- **Logging:** `_handle_load_dialog` logs `value=%r`; refusals log `%r`.
- **Targeted runs:** 21 passed, 1 skipped in the first batch. The skip is an arm whose name the volume refuses, because my scratch path is long (MAX_PATH; environment, not a defect). Then 16 passed + 1 skipped (the same arm), 4 passed and 2 passed. The full suite and the touched modules were `not-run` (out of scope by instruction).

**Accepted or out of scope (backlog, no finding)**
- **R2-N3b race** between the gate and `read_project_manifest`'s open: declared.
- **Folder swap after dialog open:** the preview does not re-run `_project_folder_refusal`, so a folder swapped for a junction after the dialog opened is scanned through. It needs a local writer of the work area, and the install re-checks the folder. Same class as R2-N3b.
- **Device names and source FIFOs (unverified):** a typed device name, or (POSIX) a FIFO outside W, still reaches `copy_into_workarea` after the dialog closes, as on 9a. Whether `place_into_workarea` refuses a non-regular source before reading it is not verified here (by reading, unresolved).
- **C1 characters:** a pasted C1 character shows in the `#load_path` field (the ruling covers C0 + DEL only). It is the user's own clipboard; every route that paints the typed text uses `painted_names`.

## Evidence checklist
- ✓ Each finding has what, where, why and a recommendation (columns Defect, Where, Evidence, Fix).
- ✓ Each finding has a severity and a tag.
- ✓ No secret values appear in this report. Paths are shown relative to the tree or masked (`<W>`, `<S>`).
- ✓ The verdict is explicit: PASS-WITH-NOTES. No HIGH is open. The E3 MAJORs S9b-1 and S9b-2 are applied, and I verified them with executed probes and tests.
- ✓ No new external tool or integration. The Textual command palette (built-in) was reviewed for scope under S9b-1.
