# Code-Wire graph: open-folder chip, from family to open or refusal (batch-97, PDR)

> Format B, Code-Wire draft v2.5, forward direction (PDR baseline). The node name is the code qualname, because the extractor binds a mark to the def with that qualname. This is the C11 naming rule of this project.
> The source of truth for the design is `design/design-proposal.md` (I-1, D9) and `01-requirements.md` (HLR-148, LLR-148.1 to LLR-148.4, LLR-148.8, LLR-148.10).
> A thread line with a test id comes from a recorded run at `7d823a7` (`cw_record_plugin.py`, `extract/trace-chip.json`). A line marked `synthetic` is the design example of behaviour that does not exist yet. C16 skips it.
> The main thread is `TC-704`: the `checks` chip of project `proj1`, pressed while `checks/` is missing. It is created and opened. The NEW `flows` family follows the same path (AT-B97-12).
> Convention of this graph: an edge from a node with no port to a port of a different node means that the first node computes that value in its own body and passes it. The method has no syntax for this case (see the annex, M-3).

## Nodes

OpenFolderChip.__init__
req: LLR-148.4, LLR-148.10, HLR-148
in: str family; str? id_suffix = None
out: OpenFolderChip chip {id, label, family}
func: makes the chip of one family. The id is `open_folder_<family>` or `open_folder_<family>_<suffix>`, and the label names the folder of the family
module: s19_app/tui/open_folder_chip.py
examples: (AT-B97-12, synthetic) family "checks"; id_suffix "editor" → chip {id "open_folder_checks_editor", label "📂 Open checks/"}
examples: (AT-B97-12, synthetic) family "session"; id_suffix None → chip {id "open_folder_session", label "📂 Open session"}

OpenFolderChip.refresh_target
req: LLR-148.3, HLR-148
in: OpenFolderChip self
out: None
func: resolves the target again. With no target it disables the chip and puts the no-project reason of its own family on the status line
module: s19_app/tui/open_folder_chip.py
modify: [Interface: chip state] (replace); [Interface: status line] (replace)
inner: resolve_chip_target, no_project_reason
examples: (AT-B97-13, synthetic) family "flows"; no project → chip disabled; status line names the `flows/` folder and not "Reports"

OpenFolderChip._open_target
req: LLR-148.1, LLR-148.2, LLR-148.8, LLR-148.10, HLR-148
in: OpenFolderChip self
out: None
func: resolves the target and creates a missing home of a creatable family. Then it applies the real-directory guard against the family root, and opens the folder or refuses
module: s19_app/tui/open_folder_chip.py
modify: [I/O: file system] (append); [Interface: status line] (replace)
inner: resolve_chip_target, create_chip_home, is_openable_chip_dir, open_folder_in_file_manager, no_project_reason, OpenFolderChip.refresh_target
examples: (TC-704, inferred) family "checks"; project "proj1"; `checks/` missing → `create_chip_home` makes ".../proj1/checks", then the spied seam receives it (the recorder does not see the spy)
examples: (AT-B97-12, synthetic) family "flows"; `flows` is a junction inside the project → 0 seam calls; status line refuses and names `flows/`

resolve_chip_target
req: LLR-148.1, LLR-148.2, HLR-148
in: Path? project_dir; str family; Path workarea; Path base_dir
out: Path? target
func: maps a family to its home: the project subfolder with a project, the common home without one. `reports`, `flows` and `session` have no common home
module: s19_app/tui/services/folder_open_service.py
examples: (TC-704) family "checks"; project_dir ".../proj1" → target ".../proj1/checks"
examples: (TC-703) family "checks"; project_dir None → target ".../.s19tool/workarea/patches"
examples: (AT-B97-12, synthetic) family "flows"; project_dir ".../proj1" → target ".../proj1/flows"; family "session" → target ".../proj1"

create_chip_home
req: LLR-148.1, LLR-148.2, HLR-148
in: Path? project_dir; str family; Path workarea; Path base_dir
out: Path home
func: creates the offered home of a creatable family inside its containment root and returns it. `session` never creates
module: s19_app/tui/services/folder_open_service.py
modify: [I/O: file system] (append)
inner: _path_traverses_reparse_point
examples: (TC-704) family "checks"; project_dir ".../proj1" → home ".../proj1/checks" (created)
examples: (AT-B97-12, synthetic) family "flows"; project_dir ".../proj1" → home ".../proj1/flows" (created inside the resolved project)

no_project_reason
req: LLR-148.3
in: str family
out: str reason
func: gives the English status line for a family with no target. It names the folder of that family
module: s19_app/tui/services/folder_open_service.py
examples: (AT-B97-13, synthetic) family "flows" → reason names `flows/`; family "reports" → reason equals `REPORTS_NO_PROJECT_REASON`

is_openable_chip_dir
req: LLR-148.8
in: Path target; Path root
out: bool openable
func: true only for a directory inside the resolved root. No reparse point can lie between the target and the root
module: s19_app/tui/services/folder_open_service.py
inner: _path_traverses_reparse_point
examples: (AT-B97-12, synthetic) target ".../proj1/flows" (a junction); root ".../proj1" → openable False
examples: (TC-B97-57, synthetic) target ".../.s19tool/workarea/patches"; root ".../.s19tool" (no project) → openable True

_path_traverses_reparse_point
req: LLR-148.8
in: Path path; Path? stop_at = None
out: bool traverses
func: walks the path and its parents up to `stop_at` and reports a symbolic link or junction
module: s19_app/tui/workspace.py
examples: (TC-704) path ".../proj1/checks"; stop_at ".../.s19tool" → traverses False (call from the shipped scoped_home containment check)

open_folder_in_file_manager
req: LLR-148.5, LLR-148.10
in: Path path; (Callable) (str->None)? set_status = None; str label = "folder"
out: bool opened
func: the one open seam. It starts the platform file manager on the path and puts `Opened <label>: <path>` or the failure on the status line
module: s19_app/tui/services/folder_open_service.py
modify: [I/O: file manager] (append); [Interface: status line] (replace)
examples: (TC-705) path "/tmp/some dir"; set_status None → opened True

## Entities

[Data: S19TuiApp active project]
in: Path?
desc: the project directory that the app holds, resolved at load (`app.py:1861`). It is the trust anchor of LLR-148.8

[I/O: file system]
in: Path
desc: the family homes on disk. The guard reads them and the create-on-press writes them

[I/O: file manager]
in: Path
desc: the OS file manager that the open seam starts

[Interface: status line]
in: str
desc: the app status line (`S19TuiApp.set_status`)

[Interface: chip state]
in: bool
desc: the disabled flag, the dimmed class and the tooltip of the chip

## Edges

[Data: S19TuiApp active project] ──▶ OpenFolderChip.refresh_target
[Data: S19TuiApp active project] ──▶ OpenFolderChip._open_target
[I/O: file system] ──▶ OpenFolderChip._open_target
[I/O: file system] ──▶ is_openable_chip_dir
[I/O: file system] ──▶ _path_traverses_reparse_point
OpenFolderChip.__init__.chip ──▶ OpenFolderChip.refresh_target.self
OpenFolderChip.__init__.chip ──▶ OpenFolderChip._open_target.self
OpenFolderChip.refresh_target ──▶ resolve_chip_target
OpenFolderChip._open_target ──▶ resolve_chip_target
OpenFolderChip._open_target ──▶ create_chip_home
when: target does not exist and the family is creatable
resolve_chip_target.target ──▶ is_openable_chip_dir.target
when: target exists
create_chip_home.home ──▶ is_openable_chip_dir.target
when: target was missing and is now created
OpenFolderChip._open_target ──▶ is_openable_chip_dir.root
is_openable_chip_dir ──▶ _path_traverses_reparse_point
resolve_chip_target.target ──▶ open_folder_in_file_manager.path
when: openable is True
OpenFolderChip._open_target ──▶ open_folder_in_file_manager.set_status
resolve_chip_target.target ──▶ no_project_reason
when: target is None
no_project_reason.reason ──▶ [Interface: status line]

## Findings

H-C1
anchor: resolve_chip_target.target ──▶ open_folder_in_file_manager.path
what: without a project the `checks` chip resolves to `.s19tool/workarea/patches` (recorded, TC-703), but LLR-148.10 labels it `📂 Open checks/`
evidence: `folder_open_service.py:217-218` (`_family_homes`: patch and checks share `workarea / WORKAREA_PATCHES`); trace-chip.json, test_tc703_checks_chip
consequence: HLR-148 says the chip opens "the folder the chip's label names". The no-project Check chip opens a folder named `patches/`
decision: changes I-1 (label rule): derive the label from the resolved target name, or keep the family label and amend HLR-148 / LLR-148.10

H-C2
anchor: OpenFolderChip._open_target ──▶ create_chip_home
what: the press path calls `create_chip_home` for every missing target. Nothing reads `_CREATABLE_FAMILIES`
evidence: `open_folder_chip.py:160-172`; `_CREATABLE_FAMILIES` at `folder_open_service.py:85` has 0 references in `s19_app/`
consequence: I-1 adds `flows` to a constant that has no effect. "session never creates" holds only because `_family_homes` raises `ValueError` for an unknown family. Thus a removed project directory paints `Failed to create folder: no change-1 scoped home for chip family: 'session'`, not an English refusal that names the folder (LLR-148.8)
decision: changes I-1: the `when:` of this edge must be in the code (read `_CREATABLE_FAMILIES` in the press path or in `create_chip_home`)

H-C3
anchor: OpenFolderChip._open_target ──▶ is_openable_chip_dir.root
what: the family root (the trust anchor) is computed by no named function. I-1 gives `is_openable_chip_dir(target, root)` but no producer of `root`
evidence: `01-requirements.md:68` (definition); I-1 row of `design-proposal.md:153`
consequence: the value nearest to hand in `_open_target` is `app.workarea`, but the no-project template home is `.s19tool/templates`, outside `workarea`. A root of `workarea` refuses the CRC Designer chip without a project
decision: adds one pure node to I-1, for example `chip_family_root(project_dir, base_dir) -> Path`, or a line in D9 that fixes the root to `base_dir / WORKAREA_DIRNAME`
