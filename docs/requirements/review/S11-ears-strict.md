# S11 — Projects, variants & manifest: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S11 (lines 4571–5017): 17 rows — R-TUI-012, 013, 014, R-PROJ-001, 002, R-VAR-001, 002, R-MAN-SER-001, R-MAN-WRITE-001, R-MAN-VERIFY-001, R-MAN-TUI-001, R-PROJ-ASSIGN-001, R-PROJ-ASSIGN-UI-001, R-PROJ-ASSIGN-SEC-001, R-RPT-ADDENDUM-PERSIST-001, R-RPT-REGION-PERSIST-001, 002. Also the project rows of S0's table (HLR-138 / LLR-138.1–138.4, HLR-151 / LLR-151.1, the Save-project sentence of HLR-155 / LLR-155.4, HLR-162 / LLR-162.2) and the items S5 passed (R-TUI-012, 014, R-PROJ-002, `validate_project_files`).
Code: `s19_app/tui/services/manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py`, `models.py`; the S11 functions of `app.py` (save, load, variants, sync, execute, session reset); in `workspace.py` `validate_project_files`, `build_variant_set`, `sanitize_project_name`, `is_windows_device_name`, `RESERVED_WORKAREA_HOMES`; in `screens.py` `SaveProjectScreen`, `SaveProjectPayload`, `LoadProjectScreen`, `SelectVariantScreen`. Read directly, every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows in S11.1 … S11.16, the context notes and the cites in rows and decisions this pass touched verified at 570b4b5; other cites (most S11.13 rows, untouched decisions) refer to 093a7c0. Batch input: `.dev-flow/2026-10-26-batch-100/01-requirements.md` (HLR-164, 165, 167 … 171b, 175 … 175f, 178; LLR-163.5, 163.7), its ledger and fix rounds 1–2. No test was run.

Result:
- **Context notes first** (section 3): CTX-PROJECT, CTX-SAVE, CTX-MANIFEST, CTX-LOADRES (batch-100), CTX-EXEC.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first** (TUI rule).
- Consistent with S5: the work area lives under the folder the app starts in (S5 CTX-WORKAREA), so projects live there too. Loading and unloading rules stay in S5 (sections 4.3, 4.4, 4.7); S11 cites them.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S11.md` (to be merged into `review/CODE-CHANGES.md`). Nothing is changed in the code yet.

---

## 1. How S11 was written before

- Five one-paragraph rows from the first batches (R-TUI-012, 013, 014, R-PROJ-001, 002): short, and three of them are no longer true (one S19 per project, "except the temp folder", "respecting limits").
- Two dense rows for the multi-variant model (R-VAR-001, 002): about 25 claims between them, with dataclass names, thread contracts and test oracles mixed in.
- Four manifest-writer rows (R-MAN-*) and a "design note" on where the writer module lives, why it does not call `copy_into_workarea`, and which guard tests it trips. Mostly design.
- Three save-composition rows (R-PROJ-ASSIGN-*), each half requirement, half batch record (D-KEY, D-NEWPROJ, A-5, SCOPE-1, pre-fix RED evidence).
- Three declared-region rows (R-RPT-*-PERSIST-*) with code line numbers and the `else ()` idiom.
- Nothing about the save behaviour batch-100 added (name rules, the patched image, the gather, the rollback, the session reset), although the code does all of it.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-012 | "copy the loaded file into a workarea subfolder": the save writes up to three files (image, MAC, A2L), may write a patched image instead of a copy, gathers documents and writes project.json. The folder is `<parent>/<name>` with a parent the dialog asks for; only the work area itself works as parent. | Save rows S11.2–S11.5; the save target is always the work area (D11-31). |
| R-TUI-013 | "list all project folders … except the temp folder": nine reserved homes are left out; empty folders and links are listed although they are not projects. | CTX-PROJECT defines a project; R-TUI-013.2 (D11-22). |
| R-TUI-014 | "at most one S19/HEX data file": false since multi-variant projects (any number of variants, at most one MAC, one A2L). | R-TUI-014.x (D11-2). |
| R-PROJ-001 | "the loaded data file and the loaded A2L": the MAC is saved too; the image can be a patched image. | R-PROJ-001.x, R-PROJ-IMAGE.x. |
| R-PROJ-002 | "copy it into the corresponding project folder (respecting limits)": no limits are named. S19/HEX loads become variants, a MAC is copied only when the project has none, an A2L is refused when the project has one (S2), and a file picked from the Workarea Files list is not copied at all. | R-PROJ-002.x (D11-29, D11-30). |
| R-VAR-001 | "parsed on a worker thread and applied on the main UI thread": a project load parses on the main thread; a variant activation copies the variant into `temp/` first. "A single-S19 project loads identically to before": before what? Not verifiable. | Observable rows; D11-28. |
| R-VAR-002 | "manifest absent means batch mode over all variants": with no manifest the Patch Editor's document runs in the chosen scope, and every save writes a manifest, so a saved project with an empty composition runs nothing. "exactly one ChangeSummary and/or CheckRunResult per assigned variant": one per document per variant. | CTX-EXEC; R-VAR-002.20 … (D11-25). |
| R-MAN-SER/WRITE/VERIFY-001 | Design inside the rows: stdlib encoder "never string assembly", `os.replace`, "must NOT route through `copy_into_workarea`", return shapes `(None, [finding])`, "the R-1 guard". | Observable rows; design to the design notes (D11-3). |
| R-MAN-TUI-001 | `Where the operator triggers project save`: a save is an event, not an optional feature (E4). "severity colour via the frozen `color_policy.SEVERITY_CLASS_MAP`": the notice uses the screen library's error severity. | `When`/`If` rows with exact texts. |
| R-PROJ-ASSIGN-001 | `Where the operator makes no selection` (E4); "plan tuple exactly equals `tuple(batch) + tuple(assignments[id])`" is a test oracle. | R-PROJ-ASSIGN-001.5, CTX-EXEC file list. |
| R-PROJ-ASSIGN-UI-001 | `While re-saving` is not a state of the system. The lists offer only `.json` files at the top of the project folder; the Patch Editor and the gather put documents in `patches/` and `checks/`, so in normal use nothing is offered. A re-save starts with nothing selected and erases the earlier composition. | R-PROJ-ASSIGN-UI-001.x (D11-23, D11-24). |
| R-PROJ-ASSIGN-SEC-001 | "the UI's workarea restriction is convenience, not the security boundary": design. Since batch-100 a refused write rolls the whole save back. | R-PROJ-ASSIGN-SEC-001.1, R-PROJ-ROLLBACK.x. |
| R-RPT-REGION-PERSIST-001 | "the save's verify leg is deliberately not threaded": design; the verify never compares `declared_regions`. | R-MAN-VERIFY-001.3 (D11-35). |
| R-RPT-REGION-PERSIST-002 | `else ()`, a widget id and "exact inverse format of `_parse_declared_regions`": code. Regions typed in hex come back in decimal. | R-RPT-REGION-PERSIST-002.x (D11-41). |
| §17 design note, "Status:", "Validation:" | Process records (batch ids, HLR/LLR/TC ids, test counts, signed balances). | Out of the chapter (D11-1). |

---

## 3. Context notes (informative)

### CTX-PROJECT · Projects and variants (S11.1, S11.6 … S11.8)

```text
project          A folder directly in the work area (S5 CTX-WORKAREA) that is not a
                 reserved home, whose name does not end in a dot or a space, that is
                 not a link and resolves inside the work area, and that holds a
                 project.json that is a regular file or at least one project file.
project name     The project folder's name.
reserved home    temp, patches, templates, logs, crc, flows, flowsets, splits,
                 reports; compared ignoring case.
project file     A regular file directly in the project folder, not a link, whose kind
                 (S5 CTX-FILES) is S19, Intel HEX, MAC or A2L.
data file        A project file of kind S19, Intel HEX or MAC.
variant          An S19 or Intel HEX project file.
A2L-only project A project with one A2L file and no data file.
variant order    By file name ignoring case, then by file name.
variant id       The variant's file name without its last extension; the full file
                 name when two variants share that stem (fw.s19 and fw.hex).
active variant   The variant whose image the session shows.
recorded variant The variant that project.json names as active_variant.
readable image   A variant file that reads as an S19 or Intel HEX image with at least
                 one data byte.
next valid       Starting at the recorded variant (at the first variant when the
variant          recorded one is not a variant of the project) and going on in
                 variant order, wrapping to the first: the first variant that is a
                 readable image.
open project     The project the session last loaded or saved; none at start.
project homes    patches/ (change documents), checks/ (check documents), templates/
                 (CRC templates). Other subfolders (flows/, flowsets/, reports/,
                 splits/, crc/) belong to other screens.
project document A .json file other than project.json, directly in the project
                 folder, in patches/ or in checks/; named by its entry (CTX-MANIFEST).
session state    The loaded primary, MAC and A2L; the Patch Editor document with its
                 undo history; the declared regions; the last comparison and check
                 spec; the last flow run; the last execution; the report filter; the
                 CRC template record; the A2L and MAC view state; the issue list.
count words      In texts below, "<n> entries" stands for "1 entry" when n is 1; the
                 same for files, problems, variants and bytes.
painted name     As S7 CTX-LOADDLG defines it (the same rule paints project names):
                 the characters of the Unicode categories Cc, Cf, Zl and Zp
                 removed, each unpaired surrogate replaced by U+FFFD, clipped to
                 120 characters.
painted list     Painted names joined by ", "; after the 10th name, ", and <k> more"
                 (k: the names not shown).
```

### CTX-SAVE · Saving a project (S11.2 … S11.5, S11.14)

```text
Save dialog      The title "Project name"; the name box (placeholder "letters,
                 digits, - and _"); the target line; the summary; when the open
                 project has variants and the dialog has documents to offer,
                 "Project-wide batch files (.json):" with the batch list and one
                 "Assign files to '<variant id>':" list per variant; the buttons
                 "Save (alt+s)" and "Cancel (esc)".
confirm Save     Pressing Save, alt+s, or Enter in the name box.
typed name       The text in the name box.
clean name       The typed name without the whitespace around it, keeping only
                 letters and digits (any script), - and _.
device name      A name whose part before the first dot, with trailing spaces and
                 dots removed and the digits ¹ ² ³ read as 1 2 3, is CON, PRN, AUX,
                 NUL, CONIN$, CONOUT$, COM0-COM9 or LPT0-LPT9, ignoring case.
name limit       64 characters of clean name.
path limit       length of the work-area path + 1 + length of the clean name + 53
                 must be at most 259 (53 is the longest file name a project later
                 receives, a before/after report).
save target      <work area>/<clean name>; when the clean name is the open project's
                 name ignoring case and no folder has exactly the clean name, the
                 open project's folder under its own spelling.
target line      <painted clean name> — <target kind>
target kind      new folder                         the save target does not exist
                 updates the open project           it is the open project's folder
                 merges into an existing project    it is another folder that holds
                                                    a project
                 new project in an existing folder  it is a folder that holds no
                                                    project
save as          A save to a new folder while a project is open.
merge            A save whose target kind is "merges into an existing project".
session document The change or check document open in the Patch Editor (S10) when
                 the save starts.
used document    The session document, when its file is outside the project folder.
used template    The CRC template last loaded in the CRC Designer (S13), when its
                 file is outside the project folder.
gather finding   GATHER-SOURCE-MISSING  warning  a used document or template no
                                                 longer exists
                 GATHER-CONTAINMENT     warning  a project home failed the work-area
                                                 checks, or the copy failed
patched image    The Patch Editor's change document applied again to the source's
                 data (S8).
saved image      The patched image when it differs from the source's data;
                 otherwise the source file.
image description
                 Saved image is the patched image:
                   <source file name> + <n> change entries, <k> applied by this save
                   n: entries the patched image carries; k: of those, the entries no
                   apply had written before the save.
                 Otherwise: <source file name> unchanged copy
image clause     Empty when the saved image is the source file; otherwise
                  — <image description>
save plan        What the save will write, decided before anything is written: the
                 save target and its target kind; one row per file the save writes
                 or keeps (the saved image, the MAC, the A2L, the session document,
                 and for a save as each top-level file it copies); one row per
                 sub-folder a save as copies; the links a save as skips; one row for
                 project.json. Or the refusal text of the first failed save check.
                 The gather of S11.4 (used template, composition documents) is
                 outside the plan.
action word      new      the save writes the file
                 keep     the folder already holds the file with the same content;
                          nothing is written
                 merge    project.json of a merge, rewritten
                 rewrite  project.json of another existing target, rewritten
plan file row    <label> <landing> — <action word>; when the source's name differs
                 from the landing: <label> <source file name> → <landing> — <action
                 word>. label: image · MAC · A2L · document · file; landing: the path
                 relative to the save target. Names are painted names.
summary rows     In this order:
                   the open project's folder name, when a save as finds it gone;
                   the dropped-document line of R-PROJ-DOC.13;
                   the image description, while a data file is loaded;
                   the pending line;
                   one plan file row per file row of the save plan;
                   one sub-folder row per sub-folder a save as copies;
                   the links row;
                   the active-variant row;
                   the project.json row.
pending line     unsaved changes in <image file name>
sub-folder row   folder <name>/ (<n> files) — new
links row        links or junctions not copied: <painted list>
active-variant   active variant <variant id> (before: <recorded variant id, or
row              none recorded>)
project.json row project.json — <action word>; when the target's project.json has a
                 keep reason, followed by
                 ; the current one <keep reason>, a copy is kept as
                 project.json.previous-<UTC>
keep reason      is damaged · was written by a newer version · was written by an
                 unknown version · holds keys this version does not know · holds a
                 change document path this version cannot use
backup name      project.json.previous-<YYYYMMDD>T<HHMMSS>Z (UTC); -1 … -9 is added
                 when that name is taken.
copy cap         256 MiB per file (the copy limit of S5).
save size        For a save to a new folder: every file the save writes or copies,
                 each rounded up to a multiple of 4 096 bytes, plus 65 536 bytes for
                 project.json and the folders. Nothing reached through a link counts.
refusal text     The text of a failed save check, listed below. The Save dialog
                 paints it as it is; a status line puts "Project NOT saved: " before
                 it (C-1 excepted).
save checks      In this order, with the refusal text of each:
  C-1   nothing is loaded
          (status only) Nothing to save: load a data file or A2L first.
  C-2   the clean name is empty
          name is empty — type a project name.
  C-3   the typed name, a part of it between / or \, or the clean name is a device
        name
          '<painted typed name>' is a device name — choose another name.
  C-4   the clean name is a reserved home
          '<clean name>' is a reserved name — choose another name.
  C-5   the clean name is longer than the name limit
          name too long (at most 64 characters) — shorten the name.
  C-6   the path limit is broken
          path too long — shorten the name.
  C-13  the work area cannot be listed
          the work area could not be read — check that the folder can be opened,
          then save again.
  C-7   a project that is not open has the clean name ignoring case, and the typed
        name differs from that project's name
          '<painted typed name>' is already a project as '<painted project name>'
          — choose another name.
  C-8   a loaded file no longer exists
          source file missing: <painted file name> — reload it or remove it from
          the project.
  C-12  a loaded file cannot be read
          <painted file name> could not be read: <reason> — check that the file
          can be opened, then save again. Nothing written.
  C-10  the change document holds blocked entries (S8)
          <n> blocked entries (<addresses>) — fix them in the Patch Editor.
          (each address 0x and 8 hex digits, joined by ", ")
  C-11  the saved image would be patched, and the image is neither S19 nor
        Intel HEX
          a patched <image kind> image cannot be written — only S19 and HEX images
          carry change entries.
  C-9   the save target exists and is a link
          '<clean name>' is a link or junction — choose another name.
  C-14  the save target cannot be inspected
          '<painted clean name>' could not be read — check that the folder can be
          opened, then save again.
  C-15  save as: the open project's folder is a link, cannot be inspected or is
        outside the work area
          the open project folder '<painted folder name>' <is a link or junction ·
          could not be read · is outside the work area> — pick a project in the
          list.
  C-16  save as: over 2 000 files to copy, a tree of over 10 000 entries, or a
        folder over 32 levels deep
          '<painted folder name>' has too many files to copy (over 2 000) — move
          files out of the project, then save again.
          '<painted folder name>' has too many files to copy (over 10 000 entries)
          — move files out of the project, then save again.
          '<painted folder name>' has folders nested too deep (over 32 levels) —
          move files out of the project, then save again.
  C-17  save as: a sub-folder cannot be listed or an entry cannot be classified
          <painted list of entries> could not be read — check that they can be
          opened, then save again.
  C-18  the target holds a MAC file and the session's MAC file is another file
          '<painted target name>' already has a MAC file (<painted list>) —
          choose another name.
  C-19  the target holds an A2L file that is neither the session's A2L file nor a
        file of the same name with the same bytes
          '<painted target name>' already has an A2L file (<painted list>) —
          choose another name.
  C-20  a file of the session is larger than the copy cap
          <painted file name> is too large to copy (over 256 MiB) — a project
          cannot hold files over 256 MiB.
  C-21  save as: a file to copy is larger than the copy cap
          <painted path> is too large to copy (over 256 MiB) — move it out of the
          project folder, then save again.
  C-22  merge: the target holds more than one MAC or more than one A2L file
          Project already has more than one MAC file.
          Project already has more than one A2L file.
  C-23  save to a new folder: the save size is larger than the free space of the
        work area's volume
          not enough free space (needs <n> bytes, <m> free) — free disk space or
          remove files from the project.
  C-24  save to a new folder: the free space cannot be read
          could not save — the free space of the work area could not be read —
          check the folder.
created by the save   A file or folder that did not exist before the save started
                 and that the save wrote.
document reasons Why the session document is not recorded (R-PROJ-DOC.10):
                 it is in the project's <home> folder, but its name is not one
                 project.json records · it is in the project but not in its <home>
                 folder · its file is missing or is a link · the file could not be
                 read · it could not be placed in the project's <home> folder
drop reasons     Why a carried active_document is dropped (R-PROJ-DOC.13):
                 the file is missing · the file is a link · the file is not a change
                 or check document the app can read
```

### CTX-MANIFEST · project.json (S11.9 … S11.12)

```text
manifest         <project folder>/project.json: UTF-8 JSON text, one object, indented
                 by 2 spaces, keys in this order:
  schema_version    1. Version 1 is the only version.
  active_variant    The active variant's id; null when the project has no variant.
  batch             Array of entries: documents for every in-scope variant (CTX-EXEC).
  assignments       Object: variant id -> array of entries for that variant.
  declared_regions  Optional. Array of {"name": text, "start": number, "end": number}.
  gathered          Optional. Object: patches, checks, templates -> sorted array of
                    the entries gathered into that home.
  files             Optional. Object: entry of a recorded file -> {"size": number,
                    "sha256": 64 lowercase hex digits}.
  derived_from      Optional. Object: entry of a patched variant -> {"base": the
                    base's file name, "sha256": the base's SHA-256, "differ": the
                    number of bytes that differ from the base}.
  active_document   Optional. The entry of the session document:
                    patches/<name>.json or checks/<name>.json.
recorded file    A project file directly in the project folder with a data or A2L
                 suffix, and the file active_document names.
entry            A path relative to the project folder, written with / separators.
unsafe entry     An entry that is empty or not a string; holds a NUL character or a
                 ':'; has a drive or a root (C:\x, /x); has a part that ends in a dot
                 or a space or is a device name (CTX-SAVE); is longer than 32 767
                 characters or has more than 32 parts; resolves outside the project
                 folder; or passes through a link inside it.
context          Where an entry sits, as messages name it: batch ·
                 assignments['<variant id>'] · gathered['<home>'] · files ·
                 derived_from · active_document.
region rules     name: text, not empty once control characters and terminal escape
                 sequences are removed; start: whole number, at least 0; end: whole
                 number, at least start.
read cap         1 MiB (1,048,576 bytes).
entry cap        1 000 entries in each of batch, declared_regions, files and
                 derived_from; 1 000 keys and 1 000 entries in total in each of
                 assignments and gathered.
finding bound    At most 100 skipped-entry findings are recorded one by one; the rest
                 are counted in one finding.
manifest finding A finding (S3 CTX-ISSUE) with artifact "manifest":
  MANIFEST-SIZE-CAP           error    the file is over the read cap
  MANIFEST-JSON-PARSE         error    the file is not readable, well-formed JSON
  MANIFEST-BAD-STRUCTURE      error    a key or an entry has the wrong type, or a
                                       key is over the entry cap
  MANIFEST-PATH-ESCAPE        error    an unsafe entry, on read
  MANIFEST-WRITE-ESCAPE       error    an unsafe entry, on write
  MANIFEST-WRITE-CONTAINMENT  warning  project.json is outside the work area, passes
                                       through a link, or cannot be written
damaged manifest A manifest whose read gives MANIFEST-SIZE-CAP or MANIFEST-JSON-PARSE,
                 whose top level is not an object, or with a key over the entry cap.
carried records  batch, assignments, declared_regions, gathered, derived_from and
                 active_document of a manifest that is not damaged, as entries
                 relative to the project folder.
rewrite refusal  A reason not to rewrite an existing project.json: a keep reason
                 (CTX-SAVE), or "holds entries that were skipped".
finding line     [<code>] <severity>: <message>      (severity: error, warning)
```

### CTX-LOADRES · The result of a project load (S11.6, S11.15, S11.16)

```text
problem          One finding about one file of a loaded project: a problem word, the
                 file, a reason in user terms and a next step.
problem words    In precedence order, highest first:
                   manifest damaged · no project.json    (same rank)
                   missing
                   not readable
                   changed on disk
                   not recorded
                   no digests saved
next step        manifest damaged   Save project rewrites it
                 no project.json    Save project writes it
                 missing            restore the file, or Save project to drop it
                 not readable       replace the file, or Save project to drop it
                 changed on disk    Save project records the new state
                 not recorded       Save project records it
                 no digests saved   Save project records them
                 Exceptions: the project's A2L left out (link or over the copy
                 cap): replace the A2L file, then Load again · the active document
                 too large to reopen: open it from the Patch Editor (it can take a
                 while) · the active document that could not be read now: check
                 that the file can be opened, then Load again.
problem reasons  manifest damaged: too large to read - defaults used · not valid JSON
                   - defaults used · not a manifest object - defaults used · too
                   many recorded entries - defaults used · a recorded entry has the
                   wrong shape · a file path points outside the project · a file
                   path is not a plain name in the project · a file path goes
                   through a link or junction
                 missing: recorded in project.json, not on disk · recorded as the
                   active variant
                 not readable: not a regular file · the file cannot be read · not
                   an S19 or HEX file · 0 data bytes · link or junction · too large
                   to open · could not be read · the file is a link and is not
                   opened · too large to reopen · not a change or check document
                   the app can read · the recorded change document path is not one
                   the app can use
                 changed on disk: saved <n> B, now <m> B · same size (<n> B),
                   different content
                 not recorded: in the project, not in project.json
load reason      recorded          recorded as the active variant (the latest saved)
                 none recorded     the first variant by name (the manifest records
                                   no active variant)
                 manifest damaged  the first variant by name (the manifest could
                                   not be read)
                 no project.json   the first variant by name (the project has no
                                   project.json)
                 next valid        the next valid variant (the recorded one is
                                   missing or not readable)
relation line    patched, <n> bytes differ from <base>
                   (files records a file named <base> with the recorded SHA-256)
                 patched from <base> (not in this project); <n> bytes differ from it
                   (otherwise)
load target      <opened variant file name> + <MAC file name>; one of the two when
                 the other is absent; (no image) when both are absent.
load position    variant <k> of <n> when an image opened (k: its place in variant
                 order); <n> variants otherwise.
file status      Loaded project '<project name>' -> <load target>
summary line     Loaded project '<project name>' -> <load target> - <load position>,
                 <p> problems - details: p
Load-result      Title: Project <project name> opened, followed by
panel              " with <p> problems" when p is not 0.
                 Summary grid: Opened <opened file name, or (no image)>; the load
                   reason; the relation line, when derived_from records the opened
                   variant; Variants <n> in the project; Others: one other variant
                   file name per line, followed by "   not readable" when it did not
                   read; MAC <file name, or (none)>; A2L <file name, or (none)>.
                 Heading: Problems found (the rest loaded) · No problems found.
                 One problem row per problem:
                   "  ! <problem word>: <file>  <reason> - <next step>"
                 Buttons: Select variant (v) · Close (esc).
problem bound    At most 102 problem rows; the rest are counted in one row:
                 "  ! more problems: <h> more files  not listed one by one - each has
                 one of the problems above"
```

### CTX-EXEC · Executing over variants (S11.13)

```text
Execute controls The Patch Editor's "Execute over variants" row (S10): the Scope
                 button cycles active variant · all variants · per assignment;
                 "Execute scope" runs it. Status lines name the scope by its token:
                 active · all · assignments.
in-scope variants  active: the active variant · all: every variant · assignments:
                 every variant whose assignments list is not empty.
file list        For each in-scope variant, in this order:
                   the manifest names a file, scope active or all:
                     batch, then assignments[<variant id>]
                   the manifest names a file, scope assignments:
                     assignments[<variant id>]
                   no manifest, or a manifest that names no file (D11-25):
                     the Patch Editor's document
patched name     <variant id>-patched.s19 (S19 variant) · <variant id>-patched.hex
                 (Intel HEX variant)
```

---


## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested** (test name given), **Yes; untested**, **Partly** / **No** with the decision.

### S11.1 · Projects and their files (CTX-PROJECT)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-014.3 | U | The system shall accept a project with any number of variants. | Yes; tested (`test_three_s19_variants_accepted_in_deterministic_order`). |
| R-TUI-014.1 | If | If a project folder holds more than one MAC file, then the system shall show the status `Project already has more than one MAC file.` | Partly: shown on project load, and as check C-22 on a merge save (tested: `test_variants_with_two_mac_files_still_rejected`, `test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog`); Execute scope and a later load into the project skip the rule silently (D11-39). |
| R-TUI-014.2 | If | If a project folder holds more than one A2L file, then the system shall show the status `Project already has more than one A2L file.` | Partly: shown on project load, save and A2L load (tested: `test_two_a2l_files_still_rejected`); Execute scope and a later S19, HEX or MAC load into the project skip the rule silently (D11-39). |
| R-TUI-014.4 | U | The system shall take as project files only the regular files directly in the project folder that are not links. | Yes; tested (`test_populated_reports_subdirectory_is_neutral`; links: `test_tc_b100_31_links_are_skipped_and_named`, `test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed`). |
| R-TUI-014.5 | U | The system shall give each variant the variant id of CTX-PROJECT. | Yes; tested (`test_duplicate_stem_ids_become_filenames`). |
| R-TUI-014.6 | U | The system shall list a project's variants in variant order. | Yes; tested (`test_build_variant_set_orders_variants_and_defaults_active_to_first`). |
| R-PROJ-CONTAIN.1 | U | The system shall write no byte outside the work area when it saves a project, saves back into the open project, adds a file to the open project or writes project.json. | Yes; tested (`test_tc_b100_62_variant_append_root_refuses_another_workarea`, `test_tc_b100_62_save_copies_root_refuses_another_workarea`, `test_tc_b100_69_sec4_junction_save_back_stages_in_this_work_area`, `test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it`). |

### S11.2 · Save: dialog, name and target (CTX-SAVE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-012.1 | When | When the operator presses `s` or Ctrl+S while a data file or an A2L file is loaded, the system shall open the Save dialog. | Yes; tested (`test_tc_b100_49_an_a2l_alone_opens_the_dialog`, `test_at_b100_16_save_dialog_open_folder_clash_empty_escape`). Refused while a session action runs: S6 R-BUSY-REFUSE.1. |
| R-TUI-012.2 | When | When the operator presses Cancel or escape in the Save dialog, the system shall close the dialog without saving. | Yes; tested (`test_tc_b100_49_escape_from_each_focus_position`, `test_tc_b100_49_cancel_closes_with_no_result`, `test_tc_b100_49_escape_after_a_refusal_closes`). |
| R-TUI-012.3 | If | If the operator confirms Save while the clean name is empty, then the system shall keep the Save dialog open. | Yes; tested (`test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why`). The reason is painted by R-SAVEDLG-9 (D11-65). |
| R-TUI-012.4 | When | When the operator confirms Save, the system shall use the save target as the project folder. | Yes; tested (`test_tc_b100_48_payload_parent_is_the_work_area_under_a_long_base`). D11-31 settled by batch-100 Inc 11. |
| R-TUI-012.5 | U | The system shall run the save checks of CTX-SAVE before it creates any folder. | Yes; tested (`test_tc_b100_04_reserved_homes_refused_in_every_casing`, `test_tc_b100_59_refused_plan_writes_nothing`, `test_tc_b100_31_free_space_is_checked_before_any_folder`). |
| R-TUI-012.6 | If | If a save fails more than one save check, then the system shall give the refusal text of the first one in check order. | Yes (`app.py:10796-11117`). |
| R-TUI-012.7 | If | If check C-1 fails when the operator asks Save project, then the system shall show the status `Nothing to save: load a data file or A2L first.` | Yes; tested (`test_tc_b100_49_nothing_loaded_opens_no_dialog`). |
| R-TUI-012.22 | If | If check C-1 fails when the operator asks Save project, then the system shall open no Save dialog. | Yes; tested (`test_tc_b100_49_nothing_loaded_opens_no_dialog`). |
| R-TUI-012.8 | If | If check C-2 fails, then the system shall refuse the save with the refusal text `name is empty — type a project name.` | Yes; tested (`test_tc_b100_04_empty_names_refused`, `test_tc_b100_47_no_usable_character_painted_live`). |
| R-TUI-012.9 | If | If check C-3 fails, then the system shall refuse the save with the refusal text `'<painted typed name>' is a device name — choose another name.` | Yes; tested (`test_tc_b100_04_device_names_refused_raw_and_sanitised`, `test_tc_b100_04_device_predicate_stem_before_first_dot`, `test_tc_b100_47_device_names_raw_component_and_sanitised`). |
| R-TUI-012.10 | If | If check C-4 fails, then the system shall refuse the save with the refusal text `'<clean name>' is a reserved name — choose another name.` | Yes; tested (`test_tc_b100_04_reserved_homes_refused_in_every_casing`, `test_tc_b100_47_reserved_names_in_mixed_case`). |
| R-TUI-012.11 | If | If check C-5 fails, then the system shall refuse the save with the refusal text `name too long (at most 64 characters) — shorten the name.` | Yes; tested (`test_tc_b100_06_name_cap_boundary`, `test_tc_b100_47_name_cap_64_65_300`). |
| R-TUI-012.12 | If | If check C-6 fails, then the system shall refuse the save with the refusal text `path too long — shorten the name.` | Yes; tested (`test_tc_b100_06_path_limit_met_and_exceeded`, `test_tc_b100_47_path_limit_met_and_exceeded`). |
| R-TUI-012.13 | If | If check C-7 fails, then the system shall refuse the save with the refusal text `'<painted typed name>' is already a project as '<painted project name>' — choose another name.` | Yes; tested (`test_tc_b100_05_disguised_clash_refused_naming_both`, `test_tc_b100_05_case_only_clash_refused`, `test_tc_b100_05_case_only_match_against_another_project_refused`, `test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash`). |
| R-TUI-012.14 | If | If check C-8 fails, then the system shall refuse the save with the refusal text `source file missing: <painted file name> — reload it or remove it from the project.` | Yes; tested (`test_tc_b99_14_save_project_missing_source`, `test_tc_b100_47_missing_source_painted_at_open`, `test_tc_b100_53_a_source_that_vanished_under_the_dialog_is_refused_by_the_save_worker`). |
| R-TUI-012.15 | If | If check C-9 fails, then the system shall refuse the save with the refusal text `'<clean name>' is a link or junction — choose another name.` | Yes; tested (`test_tc_b100_05_junction_target_refused_without_writing`, `test_tc_b100_62_save_target_junction_is_refused`, `test_tc_b100_47_junction_target_writes_nothing_through_it`). |
| R-TUI-012.16 | If | If check C-10 fails, then the system shall refuse the save with the refusal text `<n> blocked entries (<addresses>) — fix them in the Patch Editor.`, each address as `0x` and 8 hex digits, joined by `, `. | Yes; tested (`test_tc_b100_17_blocked_entry_refuses_the_whole_save`, `test_tc_b100_47_blocked_entries_painted_with_addresses`). |
| R-TUI-012.17 | If | If check C-11 fails, then the system shall refuse the save with the refusal text `a patched <image kind> image cannot be written — only S19 and HEX images carry change entries.` | Yes; untested (`app.py:12438-12445`). |
| R-TUI-012.18 | If | If check C-12 fails, then the system shall refuse the save with the refusal text `<painted file name> could not be read: <reason> — check that the file can be opened, then save again. Nothing written.` | Yes; tested (`test_f2_unreadable_source_refuses_and_the_app_keeps_running`, `test_tc_b100_47_unreadable_source_painted_and_app_runs`). The text gained the next step in batch-100 (`app.py:2091-2123`). |
| R-TUI-012.23 | If | If check C-13 fails, then the system shall refuse the save with the refusal text `the work area could not be read — check that the folder can be opened, then save again.` | Yes; tested (`test_tc_b100_47_refusal_painted_in_the_dialog_before_save`, arm `workarea`). |
| R-TUI-012.24 | If | If check C-14 fails, then the system shall refuse the save with the refusal text `'<painted clean name>' could not be read — check that the folder can be opened, then save again.` | Yes; tested (`test_tc_b100_62_folder_check_permission_error_has_its_own_text`). |
| R-TUI-012.25 | If | If check C-15 fails, then the system shall refuse the save with the refusal text `the open project folder '<painted folder name>' <state> — pick a project in the list.`, the state being `is a link or junction`, `could not be read` or `is outside the work area`. | Yes; tested (`test_e4_token_row_9_open_project_swapped_for_a_junction`). |
| R-TUI-012.26 | If | If check C-16 fails, then the system shall refuse the save with the refusal text of C-16 for the limit it breaks. | Yes; tested (`test_tc_b100_31_copy_ceiling_2000_files`, `test_tc_b100_31_entry_ceiling`, `test_tc_b100_31_depth_ceiling`, `test_tc_b100_31_walker_stops_before_sorting_a_huge_folder`). |
| R-TUI-012.27 | If | If check C-17 fails, then the system shall refuse the save with the refusal text `<painted list of entries> could not be read — check that they can be opened, then save again.` | Yes; tested (`test_tc_b100_31_unreadable_entries_refuse_the_save`). |
| R-TUI-012.28 | If | If check C-20 fails, then the system shall refuse the save with the refusal text `<painted file name> is too large to copy (over 256 MiB) — a project cannot hold files over 256 MiB.` | Yes; tested (`test_tc_b100_59_plan_cap_refusal_names_the_file`). |
| R-TUI-012.29 | If | If check C-21 fails, then the system shall refuse the save with the refusal text `<painted path> is too large to copy (over 256 MiB) — move it out of the project folder, then save again.` | Yes; tested (`test_tc_b100_59_file_over_the_cap_is_refused_in_the_plan`). |
| R-TUI-012.30 | If | If check C-22 fails, then the system shall refuse the save with the refusal text of R-TUI-014.1 or R-TUI-014.2. | Yes; tested (`test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog`). |
| R-TUI-012.31 | If | If check C-23 fails, then the system shall refuse the save with the refusal text `not enough free space (needs <n> bytes, <m> free) — free disk space or remove files from the project.`, n being the save size. | Yes; tested (`test_tc_b100_31_free_space_is_checked_before_any_folder`, `test_tc_b100_47_free_space_short_by_one_and_exact`, `test_tc_b100_59_plan_total_counts_every_written_byte`, `test_tc_b100_59_plan_total_rounding_per_file`). |
| R-TUI-012.32 | If | If check C-24 fails, then the system shall refuse the save with the refusal text `could not save — the free space of the work area could not be read — check the folder.` | Yes; untested (`app.py:11104-11110`). |
| R-TUI-012.19 | If | If a save that the Save dialog did not prepare fails check C-8, C-10, C-11, C-12, C-15 … C-23, then the system shall also show the refusal as an error notice titled `Project not saved`. | Yes (`app.py:10706-10716`); in the dialog the refusal is painted instead (D11-56). |
| R-TUI-012.33 | If | If a save that the Save dialog did not prepare is refused, then the system shall show the status `Project NOT saved: <refusal text>`. | Yes; tested (`test_tc_b100_47_dialog_line_equals_the_direct_status_line`, `test_tc_b100_04_reserved_homes_refused_in_every_casing`). |
| R-TUI-012.20 | If | If the typed name is the name of an existing project that is not open, then the system shall save into that project. | Yes; tested (`test_tc_b100_05_exact_name_adds_a_variant`, `test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges`). |
| R-TUI-012.21 | If | If the clean name is the open project's name ignoring case and no folder has exactly the clean name, then the system shall save into the open project under its folder's spelling. | Yes; tested (`test_tc_b100_05_open_project_case_variant_saves_under_on_disk_name`, `test_tc_b100_05_open_project_unsanitised_name_saves_into_it`, `test_tc_b100_47_target_line_open_project_in_another_case`). |
| R-TUI-012.34 | If | If a save names a parent folder that is not the work area, then the system shall refuse the save with the status `Project NOT saved: <parent folder> is not the work area folder — choose the work area as the parent folder (<work area>).` | Yes; tested (`test_tc_b100_33_foreign_parent_is_refused_before_any_folder`). Reached only by a save the dialog did not prepare (`app.py:10683-10695`). |
| R-TUI-012.35 | If | If a save names a parent folder that does not exist, then the system shall show the status `Parent folder not found or not a directory.` | Yes; untested (`app.py:10675-10679`). |
| R-TUI-012.36 | When | When a save names the work area under another spelling as its parent folder, the system shall save into the work area. | Yes; tested (`test_tc_b100_33_work_area_under_another_spelling_saves_there`). |

#### Save dialog (from batch-100 HLR-175, HLR-175a … HLR-175f)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SAVEDLG-1 | When | When the Save dialog opens, the system shall place the focus in the name box. | Yes; tested (`test_tc_b100_49_dialog_opens_with_the_focus_in_the_name_field`). |
| R-SAVEDLG-2 | While | While a project is open, the system shall open the Save dialog with the open project's name in the name box, all of it selected. | Yes; tested (`test_tc_b100_49_open_project_name_is_offered_selected`). |
| R-SAVEDLG-3 | U | The system shall put every printable key pressed in the name box into the name box. | Yes; tested (`test_tc_b100_49_plain_letters_stay_in_the_name_field`). |
| R-SAVEDLG-4 | When | When the operator presses alt+s in the Save dialog or Enter in the name box, the system shall act as when Save is pressed. | Yes; tested (`test_tc_b100_49_buttons_show_their_keys_and_the_keys_work`). |
| R-SAVEDLG-5 | If | If the operator presses Ctrl+L, Ctrl+S, Ctrl+K or Ctrl+D while the Save dialog is open, then the system shall run no app action for that key. | Yes; tested (`test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open`). |
| R-SAVEDLG-6 | U | The system shall offer no choice of parent folder in the Save dialog. | Yes; tested (`test_tc_b100_48_no_parent_field_and_no_browse`). |
| R-SAVEDLG-7 | When | When the typed name changes, the system shall paint the target line for the new name. | Yes; tested (`test_tc_b100_47_target_line_names_the_sanitised_folder_new`, `test_tc_b100_47_target_line_open_project_kind`, `test_tc_b100_47_target_line_merge_and_existing_folder_kinds`). |
| R-SAVEDLG-8 | While | While the Save dialog is open, the system shall paint in the summary the summary rows of the save plan for the typed name. | Yes; tested (`test_tc_b100_65_summary_rows_equal_the_plan`, `test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties`, `test_at_b100_21_painted_plan_is_the_saved_tree`). |
| R-SAVEDLG-9 | If | If the save for the typed name is refused, then the system shall paint its refusal text in the target line. | Yes; tested (`test_tc_b100_47_refusal_painted_in_the_dialog_before_save`, `test_at_b100_02_name_refusals_through_the_save_dialog`, `test_at_b100_16_save_dialog_open_folder_clash_empty_escape`). |
| R-SAVEDLG-10 | If | If the save for the typed name is refused, then the system shall paint no summary row. | Yes; tested (`test_tc_b100_47_plan_refusals_replace_the_rows`). |
| R-SAVEDLG-11 | If | If the operator confirms Save while the save for the typed name is refused or its plan differs from the painted plan, then the system shall keep the Save dialog open. | Yes; tested (`test_tc_b100_49_save_during_a_refusal_keeps_the_dialog_and_save_focusable`, `test_tc_b100_65_out_of_date_save_repaints_and_stops_the_timer`). |
| R-SAVEDLG-12 | If | If the operator confirms Save while the plan for the typed name differs from the painted plan, then the system shall paint the plan for the typed name. | Yes; tested (`test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_1`, `test_tc_b100_65_active_variant_change_counts_as_out_of_date`). |
| R-SAVEDLG-13 | If | If the operator confirms Save while the plan for the typed name differs from the painted plan, then the system shall add the line `the summary changed — check it, then save again` to the target line. | Yes; tested (`test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_2`, `test_tc_b100_65_save_before_the_preview_is_shown_repaints`). |
| R-SAVEDLG-14 | When | When the operator confirms Save while the painted plan is the plan for the typed name and is not refused, the system shall close the Save dialog. | Yes; tested (`test_tc_b100_49_confirming_save_closes_and_saves`). |
| R-SAVEDLG-15 | When | When the Save dialog closes on a confirmed Save, the system shall run the save of the painted plan. | Yes; tested (`test_tc_b100_49_confirming_save_closes_and_saves`, `test_tc_b100_65_save_executes_the_painted_plan`). |
| R-SAVEDLG-16 | When | When the system runs the save of a painted plan, the system shall write exactly the files that the plan's rows name, besides the gather of S11.4. | Yes; tested (`test_tc_b100_65_save_executes_the_painted_plan`, `test_tc_b100_65_document_keep_row_is_what_the_save_writes`, `test_at_b100_21_painted_plan_is_the_saved_tree`). |
| R-SAVEDLG-17 | When | When the system runs a save that the Save dialog did not prepare, the system shall prepare the save plan for its name and run that plan. | Yes; tested (`test_tc_b100_65_a_direct_payload_saves_the_same_tree`, `test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh`). |
| R-SAVEDLG-18 | If | If a load lands while the Save dialog is open, then the system shall compute the next plan from the session after that load. | Yes; tested (`test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session`). |
| R-SAVEDLG-19 | While | While a data file is loaded, the system shall paint the image description as a summary row. | Yes; tested (`test_tc_b100_65_image_line_says_emit_or_copy`). |
| R-SAVEDLG-20 | While | While the session image differs from the image last loaded or saved, the system shall paint the pending line as a summary row. | Yes; tested (`test_tc_b100_65_pending_line_marks_unsaved_changes`). |
| R-SAVEDLG-21 | If | If the save plan skips links or junctions, then the system shall paint the links row. | Yes; tested (`test_tc_b100_65_skipped_links_get_one_row`, `test_tc_b100_59_links_only_folder_and_skipped_links`). |
| R-SAVEDLG-22 | While | While the save plan is a merge with an image row, the system shall paint the active-variant row. | Yes; tested (`test_tc_b100_65_merge_names_the_active_variant_it_sets`, `test_tc_b100_65_active_variant_stem_collision_is_predicted_exactly`). |
| R-SAVEDLG-23 | If | If the target's project.json has a keep reason, then the system shall add the keep note of CTX-SAVE to the project.json row. | Yes; tested (`test_tc_b100_65_manifest_backup_gets_its_own_row`). |
| R-SAVEDLG-24 | When | When the save plan copies the open project's sub-folders, the system shall paint one sub-folder row per sub-folder with its file count. | Yes; tested (`test_tc_b100_59_save_as_plans_one_row_per_subfolder`). |
| R-SAVEDLG-25 | While | While the summary holds more rows than it shows, the system shall keep Save and Cancel visible. | Yes; tested (`test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap`). |
| R-SAVEDLG-26 | U | The system shall let the operator scroll the summary to its last row with the keyboard alone. | Yes; tested (`test_tc_b100_65_last_row_reachable_by_keyboard`). |
| R-SAVEDLG-27 | U | The system shall paint each summary row on one line, ending a cut row with `…`. | Yes; tested (`test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap`). |
| R-SAVEDLG-28 | U | The system shall paint no internal decision id in the Save dialog. | Yes; tested (`test_tc_b100_66_save_dialog_paints_no_decision_id`). |

### S11.3 · Save: what is written

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-001.1 | When | When the system saves a project, the system shall place the saved image in the project folder. | Yes; tested (`test_save_project_creates_project_folder_on_disk`). |
| R-PROJ-001.2 | When | When the system saves a project, the system shall place a copy of the session's MAC file in the project folder. | Yes; tested (`test_tc_b100_15_mac_and_a2l_stay_byte_copies`). |
| R-PROJ-001.3 | When | When the system saves a project, the system shall place a copy of the session's A2L file in the project folder. | Yes; tested (`test_tc_b100_15_mac_and_a2l_stay_byte_copies`). |
| R-PROJ-001.4 | If | If the project folder holds a file with the same content under the file's name or a numbered name (S5), then the system shall use that file and write nothing. | Yes; tested (`test_tc_b100_59_open_project_unchanged`, `test_tc_b100_68_forced_claim_between_prediction_and_placement`). |
| R-PROJ-001.5 | If | If the file's name is taken in the project folder by a different content, then the system shall place the file under the lowest free numbered name. | Yes; tested (`test_tc_b100_15_clashing_name_lands_as_the_next_variant`). |
| R-PROJ-001.11 | If | If check C-18 fails, then the system shall refuse the save with the refusal text `'<painted target name>' already has a MAC file (<painted list>) — choose another name.` | Yes; tested (`test_tc_b100_59_second_companion_is_refused_before_any_folder`). Was `Project already has a MAC file.` (D11-73). |
| R-PROJ-001.12 | If | If check C-19 fails, then the system shall refuse the save with the refusal text `'<painted target name>' already has an A2L file (<painted list>) — choose another name.` | Yes; tested (`test_tc_b100_59_second_companion_is_refused_before_any_folder`, `test_tc_b100_59_own_a2l_by_name_and_bytes`). D11-20 settled by batch-100 Inc 8b. |
| R-PROJ-001.6 | When | When the system saves a project, the system shall make the saved image's variant the active variant. | Yes; tested (`test_save_second_s19_into_project_appends_variant`). |
| R-PROJ-001.7 | When | When the system saves a project, the system shall make it the open project. | Yes; tested (`test_save_project_writes_under_workarea`; a save as: `test_tc_b100_31_save_as_copies_every_subfolder_file`). |
| R-PROJ-001.10 | When | When the system saves a project, the system shall write the manifest (S11.10). | Yes; tested (`test_project_save_writes_and_verifies_manifest`). |
| R-PROJ-001.8 | When | When a save ends with a saved variant, the system shall show the status `Saved project to <project folder> (variant '<variant id>')<image clause>`. | Yes; tested (`test_tc_b100_16_one_applied_entry`, `test_tc_b100_16_entry_added_after_the_apply`). |
| R-PROJ-001.9 | If | If the saved project has no variant, then the system shall show the status `Saved project to <project folder><image clause>`. | Yes. |
| R-PROJ-IMAGE.1 | If | If the Patch Editor's change document gives data that differ from the source's data, then the system shall save the patched image instead of a copy of the source. | Yes; tested (`test_tc_b100_14_new_bytes_emit`, `test_tc_b100_14_unapplied_entry_emits`, `test_tc_b100_15_patched_s19_is_emitted`, `test_tc_b100_15_patched_hex_is_emitted`, `test_at_b100_05_save_project_saves_the_patched_image`). |
| R-PROJ-IMAGE.2 | If | If the Patch Editor holds a check document, then the system shall save a copy of the source. | Yes; tested (`test_tc_b100_14_check_document_copies`, `test_tc_b100_15_check_document_only_copies`). |
| R-PROJ-IMAGE.3 | If | If the change document gives the source's own data, then the system shall save a copy of the source. | Yes; tested (`test_tc_b100_14_same_bytes_copy`, `test_tc_b100_14_applied_then_undone_copies`, `test_tc_b100_15_unchanged_document_copies`). |
| R-PROJ-IMAGE.4 | When | When the system saves a patched image, the system shall name it as the source file with the extension `.s19` or `.hex` of its image kind. | Yes. |
| R-PROJ-IMAGE.5 | When | When the system has saved a patched image, the system shall show the patched image in the session. | Yes; tested (`test_at_b100_05_save_project_saves_the_patched_image`). |
| R-PROJ-IMAGE.6 | When | When the system has saved a patched image, the system shall show the verify result of S8's image save. | Yes. |
| R-PROJ-IMAGE.7 | When | When the system saves a patched image, the system shall write it as S8.7 states, with 32 data bytes in each S19 data record. | Yes; untested (`app.py:12431-12437`). |
| R-PROJ-IMAGE.8 | When | When the system saves a patched S19 image whose source has an S0 record with data, the system shall use that data as header data (S8 CTX-SAVEBACK). | Yes; untested (`app.py:12436`). |
| R-PROJ-IMAGE.9 | When | When the system saves a patched S19 image whose source has a terminator, the system shall write the address of the source's terminator in the terminator. | No: address 0 is written (D11-42; `app.py:12431-12437` passes no terminator address). |
| R-PROJ-IMAGE.10 | When | When the system has written a patched image, the system shall verify it as S8.8 states. | Yes (`app.py:9046`, the emit verifies the written file). |
| R-PROJ-IMAGE.11 | U | The system shall offer no choice of data bytes per record for Save project. | Yes (LLR-015.3; D11-53). |
| R-PROJ-IMAGE.12 | When | When a Save project completes, the system shall record the session image as last saved. | Yes; tested (`test_tc_b100_58_save_project_records_the_saved_state`, `test_tc_b100_58_predicate_sequence_unit`). |
| R-PROJ-IMAGE.13 | When | When the system has saved a patched image, the system shall record in derived_from the source file as the base of the saved variant. | Yes; tested (`test_tc_b100_71_emit_records_a_base_outside_the_project`, `test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from`). |
| R-PROJ-IMAGE.14 | If | If the system saves a copy of the source, then the system shall record no derived_from for it. | Yes; tested (`test_tc_b100_71_byte_copy_records_nothing`). |

#### Merge (from batch-100 HLR-164)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-MERGE.1 | When | When the system saves into a project that is not open, the system shall keep the target's variants. | Yes; tested (`test_tc_b100_05_exact_name_adds_a_variant`). |
| R-PROJ-MERGE.2 | When | When the system saves into an existing project folder, the system shall copy none of the open project's sub-folders into it. | Yes; tested (`test_tc_b100_31_merge_and_save_into_itself_copy_no_subfolder`, `test_tc_b100_59_merge_and_open_targets_plan_no_copy`). |
| R-PROJ-MERGE.3 | When | When the system saves into an existing project folder, the system shall write into its project.json the target's carried records that the save does not set. | Yes; tested (`test_tc_b100_05_merge_carries_the_document_and_gathered`, `test_tc_b100_59_open_project_carry_sets_the_keys`, `test_tc_b100_59_merge_plans_a_merge_row`). |

### S11.4 · Save: the gather (from S0 HLR-138)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-GATHER.1 | When | When the system saves a project, the system shall copy the used document into the project home of its kind: `patches/` for a change document, `checks/` for a check document. | Yes; tested (`test_tc700_active_editor_document_is_gathered_by_kind`, `test_tc_b100_29_file_backed_document_is_copied_and_recorded`). |
| R-PROJ-GATHER.2 | When | When the system saves a project, the system shall copy the used template into `templates/`. | Yes; tested (`test_tc701_used_template_gathered_into_project_templates`). |
| R-PROJ-GATHER.3 | When | When the system gathers a file, the system shall leave the original unchanged. | Yes; tested (`test_tc699_common_change_set_is_gathered_into_project_patches`). |
| R-PROJ-GATHER.4 | If | If the project home holds a file with the same content under the file's name or a numbered name, then the system shall use that file and write nothing. | Yes; tested (`test_tc699_resave_is_idempotent_no_dedup_copies`). |
| R-PROJ-GATHER.5 | If | If the file's name is taken in the project home by a different content, then the system shall copy the file under the lowest free numbered name. | Yes; tested (`test_tc702_resave_refreshes_stale_copies`). |
| R-PROJ-GATHER.6 | If | If the used document no longer exists, then the system shall show the finding line `[GATHER-SOURCE-MISSING] warning: gather: active document <path> no longer exists — skipped`. | No: written to the log only (D11-27; re-verified `app.py:11860-11861`). |
| R-PROJ-GATHER.7 | If | If the used template no longer exists, then the system shall show the finding line `[GATHER-SOURCE-MISSING] warning: gather: active template <path> no longer exists — skipped`. | No: written to the log only (D11-27). |
| R-PROJ-GATHER.8 | If | If the copy of a used file fails, then the system shall show the finding line `[GATHER-CONTAINMENT] warning: gather: refused to copy <source> into <home>: <error type>: <reason>`. | No: written to the log only (D11-27). |
| R-PROJ-GATHER.9 | If | If a used file cannot be gathered, then the system shall go on with the save. | Yes. |
| R-PROJ-GATHER.10 | If | If the system copies into the project a file whose name project.json cannot record, then the system shall show the status `<painted name> was copied but not recorded in project.json (<why>) — rename it in the common folder, select the new name, then Save project.`, why being `Windows reserves that name` for a device name and `the name is not one project.json records` otherwise. | Yes; tested (`test_tc_b100_31_crc_template_named_con_json_is_named_unrecorded`, `test_tc_b100_31_unrecorded_name_reason_is_not_too_long`). |
| R-PROJ-GATHER.11 | If | If more than 10 copied files are not recorded, then the system shall show the status `and <k> more files not recorded in project.json` after the first 10. | Yes; untested (`app.py:12246-12250`). |

#### The Patch Editor document (from batch-100 HLR-170, HLR-167)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-DOC.1 | When | When the system saves a project while the session document has no file and at least one entry, the system shall write that document as `changes.json` in the project home of its kind. | Yes; tested (`test_tc_b100_29_pasted_document_lands_and_is_recorded`, `test_tc_b100_29_pasted_check_document_lands_in_checks`, `test_at_b100_08_saved_document_reopens_with_the_project`). |
| R-PROJ-DOC.2 | If | If that home already holds a different `changes.json`, then the system shall write the document under the lowest free numbered name (`changes_1.json` …). | Yes; tested (`test_tc_b100_29_different_changes_json_lands_as_changes_1`). |
| R-PROJ-DOC.3 | If | If that home already holds a `changes.json` with the same content, then the system shall write no document. | Yes; tested (`test_tc_b100_29_identical_changes_json_is_reused`, `test_tc_b100_29_second_save_of_the_bound_document_writes_nothing`). |
| R-PROJ-DOC.4 | If | If the session document has no file and no entry, then the system shall write no document. | Yes; tested (`test_tc_b100_29_zero_entries_writes_no_document`, `test_tc_b100_59_zero_entries_plans_no_document_row`). |
| R-PROJ-DOC.5 | When | When the save places the session document in the project home of its kind, the system shall record its entry as active_document. | Yes; tested (`test_tc_b100_29_file_backed_document_is_copied_and_recorded`, `test_tc_b100_29_file_backed_zero_entries_is_recorded`, `test_tc_b100_59_document_row_in_a_fresh_folder`). |
| R-PROJ-DOC.6 | If | If the session document's file is already in the project home of its kind, then the system shall record it as active_document without copying it. | Yes; tested (`test_tc_b100_65_document_keep_row_is_what_the_save_writes`, `test_tc_b100_59_document_row_owns_its_landing`). |
| R-PROJ-DOC.7 | If | If the session document cannot be written, then the system shall complete the save without it. | Yes; tested (`test_tc_b100_29_forced_write_failure_saves_without_the_document`). |
| R-PROJ-DOC.8 | If | If the session document cannot be written, then the system shall show the status `Change document <name> was not saved into the project — the file could not be written; its entries stay in the Patch Editor`. | Yes; tested (`test_tc_b100_29_forced_write_failure_saves_without_the_document`). |
| R-PROJ-DOC.9 | If | If the project home of the session document's kind is a link or outside the work area, then the system shall show the status `Change document changes.json was not saved into the project — the project's <home> folder is a link or is outside the work area; its entries stay in the Patch Editor`. | Yes; the refusal is tested (`test_tc_b100_29_r18_document_behind_a_junctioned_home_is_never_copied`, `test_tc_b100_29_cp1_junctioned_home_gives_no_document_row`), the text is not. |
| R-PROJ-DOC.10 | If | If the save records no session document for another reason, then the system shall show the status `Change document <name> was not recorded in the project — <document reason>`. | Yes; tested (`test_tc_b100_29_cp1_document_recorded_elsewhere_paints_one_true_line`, `test_tc_b100_29_document_inside_the_project_outside_its_home_is_not_placed`). |
| R-PROJ-DOC.11 | If | If a save into an existing project records no session document, then the system shall keep the target's active_document. | Yes; tested (`test_tc_b100_05_r3_failed_write_carries_the_target_document`, `test_tc_b100_05_merge_carries_the_document_and_gathered`). |
| R-PROJ-DOC.12 | If | If the kept active_document's file is missing, is a link, or is not a change or check document the app can read, then the system shall drop the record. | Yes; tested (`test_tc_b100_05_merge_drops_a_faulty_carried_document_with_one_line`, `test_tc_b100_05_r8_target_document_that_is_a_link_is_not_carried`). |
| R-PROJ-DOC.13 | If | If the system drops a kept active_document, then the system shall show the status `Change document record <entry> was dropped from project.json — <drop reason>`. | Yes; tested (`test_tc_b100_05_merge_drops_a_faulty_carried_document_with_one_line`). |
| R-PROJ-DOC.14 | If | If the kept active_document's file cannot be read now, then the system shall show the status `Change document <entry> could not be read — it stays recorded; check that the file can be opened, then Load again`. | Yes; tested (`test_tc_b100_05_merge_keeps_a_held_document_with_one_line`). |
| R-PROJ-DOC.15 | When | When a Save project writes the session document into the project, the system shall clear the Patch Editor's unsaved mark. | Yes; tested (`test_tc_b100_70_written_document_clears_the_flag`). |
| R-PROJ-DOC.16 | If | If a save leaves the Patch Editor's edits only in memory, then the system shall keep the Patch Editor's unsaved mark. | Yes; tested (`test_tc_b100_70_refused_save_keeps_the_flag`, `test_tc_b100_70_failed_document_write_keeps_the_flag`, `test_tc_b100_70_file_backed_document_from_outside_keeps_the_flag`, `test_tc_b100_70_unparsed_paste_text_keeps_the_flag`). |
| R-PROJ-DOC.17 | If | If the save records the session document's file as it is on disk while the Patch Editor holds unsaved edits of it, then the system shall show the status `Change document <name> has unsaved edits — the project records the file as it is on disk; save it from the Patch Editor to keep them`. | Yes; untested (`app.py:12271-12281`). |
| R-PROJ-DOC.18 | When | When the system loads a project whose project.json records an active document, the system shall open that document in the Patch Editor after the project's A2L is attached. | Yes; tested (`test_tc_b100_30_reopen_lists_the_recorded_document`, `test_tc_b100_30_reopen_resolves_a_symbol_against_the_project_a2l`, `test_at_b100_08_saved_document_reopens_with_the_project`). |
| R-PROJ-DOC.19 | When | When the system reopens the recorded document, the system shall apply none of its entries. | Yes; tested (`test_tc_b100_30_reopen_never_applies_the_entries`). |
| R-PROJ-DOC.20 | When | When the system reopens the recorded document, the system shall leave the Patch Editor's unsaved mark clear. | Yes; tested (`test_tc_b100_30_reopened_document_loads_without_a_question`, `test_tc_b100_70_project_load_asks_only_while_the_document_is_unsaved`). |
| R-PROJ-DOC.21 | If | If the recorded document is a link, is larger than 1 MiB, holds more than 1 000 entries, is not a change or check document the app can read, or cannot be read, then the system shall list it as a `not readable` problem. | Yes; tested (`test_tc_b100_30_linked_document_is_one_not_readable_row`, `test_tc_b100_30_truncated_document_is_one_not_readable`, `test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second`, `test_tc_b100_30_held_document_is_not_readable_and_stays_recorded`, `test_tc_b100_30_classifier_outcome`). |
| R-PROJ-DOC.22 | If | If the recorded document is listed as a problem, then the system shall open no document in the Patch Editor. | Yes; tested (`test_tc_b100_30_refused_record_is_one_not_readable_row_and_no_reopen`). |

### S11.5 · Save: failure after the folder exists

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-ROLLBACK.1 | If | If a save fails after the system has created the project folder, then the system shall remove the project folder. | Yes; tested (`test_tc_b100_07_forced_oserror_leaves_no_folder`, `test_tc_b100_07_failed_verify_leaves_no_folder_fresh`). |
| R-PROJ-ROLLBACK.2 | If | If a save fails, then the system shall remove every file and folder created by the save. | Yes; tested (`test_tc_b100_07_failed_save_removes_every_placed_path`, `test_tc_b100_07_failed_merge_removes_placed_files`, `test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left`, `test_tc_b100_29_failure_after_the_write_removes_the_document`). |
| R-PROJ-ROLLBACK.3 | If | If a save fails, then the system shall keep every file and folder that existed before the save. | Yes; tested (`test_tc_b99_14_preexisting_folder_survives_placement_failure`, `test_tc_b100_07_empty_preexisting_home_survives_failed_save`). |
| R-PROJ-ROLLBACK.4 | If | If a save fails after it has replaced project.json, then the system shall put the previous project.json back. | Yes; tested (`test_tc_b100_07_failed_verify_restores_previous_manifest`). |
| R-PROJ-ROLLBACK.5 | If | If a save fails, then the system shall keep the open project and its active variant as they were before the save. | Yes. |
| R-PROJ-ROLLBACK.6 | If | If a save fails with an operating-system error, a locked file or a refused destination, then the system shall keep running. | Yes; tested (`test_f2_unreadable_source_refuses_and_the_app_keeps_running`, `test_tc_b100_07_each_save_stage_failure_on_the_worker_rolls_back`). |
| R-PROJ-ROLLBACK.7 | If | If the patched image cannot be written, then the system shall show the status `Project NOT saved: could not save — the patched image was not written: <reason>`. | Yes; tested (`test_tc_b100_17_verify_reread_failure_rolls_the_emit_back`). |
| R-PROJ-ROLLBACK.8 | If | If a file lands at another place than the system predicted before the save, then the system shall show the status `Project NOT saved: the plan named <path> (<new or keep>) but the file landed at <path> (<new or keep>) — save again.` | Yes; tested (`test_tc_b100_59_landing_that_differs_from_its_row_rolls_back`, `test_tc_b100_68_forced_claim_between_prediction_and_placement`). |
| R-PROJ-ROLLBACK.9 | If | If project.json cannot be written, then the system shall show the status `Project NOT saved: could not save — project.json was not written. check the folder.` | Yes; tested (`test_tc_b100_17_failed_manifest_write_adopts_nothing`). |
| R-PROJ-ROLLBACK.10 | If | If a file of the save stays locked, then the system shall show the reason of S5 R-TUI-002.6 as the status. | Yes; tested (`test_tc_b99_14_placement_failure_removes_created_folder`). |
| R-PROJ-ROLLBACK.11 | If | If the work-area checks refuse a destination of the save, then the system shall show the status `Cannot save project: <reason>`. | Yes; the refusal is tested (`test_tc_b100_62_save_copies_root_refuses_another_workarea`), the status text is not. |
| R-PROJ-ROLLBACK.12 | If | If an operating-system error stops the save, then the system shall show the status `Project NOT saved: could not save — <error>. check the folder.` | Yes; tested (`test_tc_b100_07_forced_oserror_leaves_no_folder`). |
| R-PROJ-ROLLBACK.13 | If | If an operating-system error or a locked file stops the save, then the system shall also show the refusal as an error notice titled `Project not saved`. | Yes. |
| R-PROJ-ROLLBACK.14 | If | If a failed save's rollback finds a file it wrote under a folder that is now a link, or a file that is no longer the one it wrote, then the system shall keep that file. | Yes; tested (`test_tc_b100_31_rollback_never_deletes_through_a_swapped_folder`, `test_tc_b100_07_rollback_never_touches_junction_target`, `test_tc_b100_07_rollback_keeps_concurrent_writer_file_r8`). |
| R-PROJ-ROLLBACK.15 | If | If a failed save's rollback keeps a file it wrote, then the system shall show the status `Not removed after the failed save: <painted list> — a folder changed while saving; check the project folders.` | Yes; tested (`test_tc_b100_31_rollback_never_deletes_through_a_swapped_folder`). |
| R-PROJ-ROLLBACK.16 | If | If a failed save cannot put the previous project.json back, then the system shall show the status `project.json could not be restored; its previous content is kept as <backup name> in <project folder> - rename it to project.json`. | Yes; tested (`test_tc_b100_07_failed_restore_keeps_the_previous_manifest`, `test_tc_b100_07_restore_status_paints_no_exception_class`). |
| R-PROJ-ROLLBACK.17 | If | If a save fails, then the system shall keep the session image as it was before the save. | Yes; tested (`test_tc_b100_53_save_adopts_only_after_the_commit`, `test_tc_b100_17_failed_manifest_write_adopts_nothing`). |
| R-PROJ-ROLLBACK.18 | If | If an error other than an operating-system error stops the save, then the system shall show the status `Project NOT saved: could not save — an unexpected error stopped the save. check the folder.` | Yes; tested (`test_tc_b100_54_save_worker_non_os_error_rolls_back_and_reports`, `test_tc_b100_51_save_failure_paints_its_lines_then_its_outcome`, `test_tc_b100_50_save_raise_ends_the_action_first`). |

### S11.6 · Load project (from S0 HLR-162; batch-100 HLR-165, HLR-171b)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-013.2 | U | The system shall list in the Load dialog's projects section only the projects of CTX-PROJECT. | Yes; tested (`test_tc_b100_04_list_projects_omits_reserved_homes_casefolded`, `test_tc_b100_62_listing_leaves_out_links_and_junctions`, `test_tc_b99_35_reserved_homes_are_not_projects`, `test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed`, `test_tc_b100_38_project_list_skips_a_name_ending_in_a_dot_or_space`, `test_tc_b100_38_project_list_leaves_a_trailing_dot_name_out_off_windows`, `test_tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform`, `test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it`). D11-22 settled by batch-100 Inc 8b and 9b. |
| R-TUI-013.6 | If | If the chosen project folder no longer exists, then the system shall show the status `Project not found: <painted project name>`. | Yes; untested (`app.py:13327-13330`). |
| R-TUI-013.7 | If | If the project folder breaks rule R-TUI-014.1 or R-TUI-014.2, then the system shall load nothing from it. | Yes. |
| R-TUI-013.8 | If | If the project folder holds neither a data file nor an A2L file, then the system shall show the status `Project NOT loaded: '<painted project name>' has no data or A2L file — load a file and Save project.` | Yes; tested (`test_tc_b100_32_empty_folder_is_refused_before_any_reset`). D11-21 settled by batch-100 Inc 8b. |
| R-TUI-013.9 | When | When the system loads a project, the system shall load its active variant, its MAC file and its A2L file. | Yes; tested (`test_project_load_activates_first_variant`, `test_tc_b100_25_load_reports_the_case`). |
| R-TUI-013.10 | If | If the project has no variant, then the system shall load its MAC file as the session's MAC. | Yes; untested. |
| R-TUI-013.11 | When | When the system loads a project, the system shall make it the open project. | Yes; tested (`test_load_project_button_loads_the_picked_project`, `test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l`). |
| R-TUI-013.12 | When | When a project load completes, the system shall set the file status to the file status of CTX-LOADRES. | Yes; tested (`test_tc_b100_56_one_summary_line_and_the_final_status_text`, `test_tc_b100_56_project_line_is_the_file_state_painted_at_the_last_end`). |
| R-TUI-013.13 | When | When a project load completes, the system shall show the summary line of CTX-LOADRES as the status. | Yes; tested (`test_tc_b100_56_one_summary_line_and_the_final_status_text`, `test_tc_b100_10_no_discard_notice_when_nothing_unsaved`, `test_tc_b100_26_active_deleted_the_other_opens`). |
| R-TUI-013.14 | If | If reading the manifest during a project load gives manifest findings, then the system shall list each as a problem of CTX-LOADRES. | Yes; tested (`test_at_b100_07_load_names_the_changed_file_and_the_hostile_record`, `test_tc_b100_67_damaged_manifest_paints_user_terms_only`). D11-26 superseded by D11-61. |
| R-TUI-013.15 | If | If the picked project folder is a link, then the system shall show the status `Project NOT loaded: '<painted project name>' is a link or junction — pick a project in the list.` | Yes; tested (`test_tc_b100_62_load_refuses_a_junction_project`). |
| R-TUI-013.16 | If | If the picked project folder is not a folder directly in the work area or resolves outside it, then the system shall show the status `Project NOT loaded: '<painted project name>' is outside the work area — copy the folder into the work area.` | Yes; tested (`test_tc_b100_62_load_refuses_a_folder_outside_the_work_area`). |
| R-TUI-013.17 | If | If the picked project folder, its file list or its project.json cannot be read, or its project.json is not a regular file, then the system shall show the status `Project NOT loaded: '<painted project name>' could not be read — check that the folder can be opened, then load again.` | Yes; tested (`test_tc_b100_62_folder_check_permission_error_has_its_own_text`, `test_tc_b100_54_project_worker_failure_keeps_the_session`, `test_tc_b100_40_unreadable_picked_project_paints_one_status_line`). The same text ends a load whose read fails on the worker. S7 R-LOADDLG.67 is retired into this row (S7 D7-34). |
| R-TUI-013.18 | If | If the picked name is not a project of the project list, then the system shall show the status `Project NOT loaded: '<painted name>' is not a project — pick a project in the list.` | Yes; tested (`test_tc_b100_32_empty_folder_is_refused_before_any_reset`, `test_tc_b100_38_project_load_of_an_unlisted_name_is_refused`). S7 R-LOADDLG.66 is retired into this row (S7 D7-34). |
| R-TUI-013.19 | If | If no variant of the project is a readable image and the project has no MAC and no A2L file, then the system shall show the status `No supported files in project: <painted project name>`. | Yes; tested (`test_tc_b100_45_refusal_lines_paint_names_literally`: the painted name, no markup; `app.py:13551-13566`). |
| R-TUI-013.20 | If | If the A2L file of a project with no data file is a link, is larger than the copy cap or cannot be inspected, then the system shall show the status `Project NOT loaded: <painted A2L file name> in '<painted project name>' <state> — replace the A2L file, then Load again.`, the state being `is a link or junction`, `is too large to open` or `could not be read`. | Yes; tested (`test_tc_b100_32_a2l_guard_of_an_a2l_only_folder`, `test_tc_b100_32_a2l_admission_refuses_any_reparse_point`). |
| R-PROJ-RESET.1 | When | When the system loads a project, the system shall clear the session state of CTX-PROJECT after it has read the project's files and before it installs the first file. | Yes; tested (`test_tc_b100_08_reset_runs_once_before_the_first_install`, `test_tc_b100_09_load_over_leaves_no_p1_state`, `test_tc_b100_09_load_over_matches_cold_outside_the_allow_list`, `test_tc_b100_53_project_over_an_open_image_equals_a_cold_load`, `test_tc_b100_53_reset_runs_after_the_worker_and_before_the_first_install`, `test_tc_b100_10_reset_leaves_the_patch_editor_clean_for_the_next_load`, `test_tc_b100_32_a2l_only_load_clears_the_previous_data_file`, `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2`). |
| R-PROJ-RESET.3 | If | If a project load is refused, then the system shall keep the session state. | Yes; tested (`test_tc_b100_32_empty_folder_is_refused_before_any_reset`, `test_tc_b100_53_project_load_refuses_cheaply_then_returns_before_the_install`, `test_tc_b100_54_project_worker_failure_keeps_the_session`). |
| R-PROJ-RESET.4 | When | When the operator loads a file outside a project load, the system shall keep the session state that S5 does not replace. | Yes; tested (`test_tc_b100_08_loose_file_load_performs_no_reset`). |

#### A2L-only projects (from batch-100 HLR-171a)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-A2LONLY.1 | When | When the system loads an A2L-only project, the system shall attach its A2L file from the project folder. | Yes; tested (`test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l`, `test_at_b100_10_a2l_only_project_saves_and_reopens`). |
| R-PROJ-A2LONLY.2 | If | If the A2L file of a project with a data file is a link or is larger than the copy cap, then the system shall open the project without that A2L file. | Yes; tested (`test_tc_b100_32_over_cap_a2l_beside_a_data_file_is_left_out`). |
| R-PROJ-A2LONLY.3 | If | If the system opens a project without its A2L file because the file is a link or is larger than the copy cap, then the system shall list that file as a `not readable` problem with the next step `replace the A2L file, then Load again`. | Yes; tested (`test_tc_b100_32_unreadable_a2l_row_paints_the_true_next_step`). |
| R-PROJ-A2LONLY.4 | If | If the project's A2L file does not parse, then the system shall open the project without that A2L file. | Yes; tested (`test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens`). |
| R-PROJ-A2LONLY.5 | If | If the project's A2L file does not parse, then the system shall list that file as a `not readable` problem with the reason `the file cannot be read`. | Yes; tested (`test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens`). |

### S11.7 · Variants

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAR-001.1 | When | When the system loads a project, the system shall make the recorded variant the active variant. | Yes; tested (`test_load_project_honors_manifest_active_variant`, `test_at_b100_06_reopen_opens_the_saved_back_variant`). |
| R-VAR-001.2 | If | If the project has no manifest or its manifest names no active variant, then the system shall make the first variant in variant order the active variant. | Yes; tested (`test_project_load_activates_first_variant`). |
| R-VAR-001.3 | If | If the recorded variant is not a variant of the project, then the system shall make the first readable image in variant order the active variant. | Yes; tested (`test_load_project_unknown_active_variant_falls_back`, `test_tc_b100_55_next_valid_when_the_recorded_one_is_missing`). |
| R-PROJ-OPEN.1 | If | If the recorded variant is not a readable image, then the system shall make the next valid variant the active variant. | Yes; tested (`test_tc_b100_26_active_deleted_the_other_opens`, `test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on`). |
| R-PROJ-OPEN.2 | If | If no variant of the project is a readable image, then the system shall load the project's MAC and A2L files without an image. | Yes; tested (`test_tc_b100_26_every_image_deleted_the_mac_opens`). |
| R-VAR-001.5 | When | When the operator presses `v`, the system shall open the Select variant dialog with the open project's variants in variant order. | Yes; tested (`test_select_variant_updates_label`). |
| R-VAR-001.6 | When | When the Select variant dialog opens, the system shall highlight the active variant and mark it ` (active)`. | Yes. |
| R-VAR-001.7 | If | If the open project has no variant when the operator presses `v`, then the system shall show the status `No project variants to select.` | Yes; untested. |
| R-VAR-001.8 | When | When the operator presses Activate in the Select variant dialog, the system shall make the highlighted variant the active variant. | Yes; tested (`test_select_variant_updates_label`). |
| R-VAR-001.9 | When | When the operator activates a variant, the system shall load the variant's file from the project folder. | Partly: the file is still copied into `temp/` and loaded from there (`app.py:8794-8800`, `15071-15110`), against S5 R-TUI-002.2; the project load itself now reads the files in place (D11-28). |
| R-VAR-001.10 | When | When the operator activates a variant, the system shall add nothing to the project folder. | Yes. |
| R-VAR-001.11 | If | If the variant's file no longer exists, then the system shall show the status `Variant file missing: <painted file name>`. | Yes; tested (`test_tc_b100_45_refusal_lines_paint_names_literally`; `app.py:8787-8792`). |

### S11.8 · Loads into an open project (R-PROJ-002)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-002.1 | When | When the operator loads an S19 or Intel HEX file while a project is open, the system shall place it in the project folder as a variant. | Partly: a file picked in the Workarea Files list or the Load dialog's work-area files is not placed (D11-29; `app.py:15619-15621`); load-dialog path loads tested (`test_load_second_s19_appends_variant`, `test_tc_b100_20_variant_append_carries_every_key_and_activates`). |
| R-PROJ-002.2 | If | If the project already holds a variant with the same content, then the system shall show the status `Variant '<variant id>' already in project '<project name>'`. | Yes; tested (`test_tc_b100_03_reused_variant_is_named_not_added`). |
| R-PROJ-002.3 | When | When the system adds a variant to the open project, the system shall show the status `Added variant '<variant id>' to project '<project name>'`. | Yes; tested (`test_tc_b100_03_reused_variant_is_named_not_added`). |
| R-PROJ-002.4 | When | When the system places an S19 or Intel HEX file in the open project, the system shall make its variant the active variant. | Yes; tested (`test_load_second_s19_appends_variant`, `test_tc_b100_20_variant_append_carries_every_key_and_activates`). |
| R-PROJ-002.5 | When | When the operator loads a MAC file while the open project has no MAC file, the system shall copy the MAC file into the project folder. | Yes; untested. |
| R-PROJ-002.6 | If | If the operator loads a MAC file while the open project holds another MAC file, then the system shall refuse the load with the status `Project already has a MAC file.` | No: the MAC loads into the session only, with no message; the next save is refused by C-18 (D11-30; re-verified `app.py:14700-14713`). |
| R-PROJ-002.7 | When | When the operator loads an A2L file while the open project has no A2L file, the system shall copy the A2L file into the project folder. | Yes; untested. The refusal when the project has one is S2 R-A2L-004.5. |
| R-PROJ-002.8 | If | If the work-area checks refuse the copy of an S19, Intel HEX or MAC file into the open project, then the system shall show the status `Project sync rejected: <reason>`. | Yes; the refusal is tested (`test_tc_b100_62_syncs_root_refuses_another_workarea`, `test_tc_b100_62_variant_append_root_refuses_another_workarea`), the status text is not. |
| R-PROJ-002.9 | If | If the work-area checks refuse the copy of an A2L file into the open project, then the system shall show the status `A2L sync rejected: <reason>`. | Yes; untested. |
| R-PROJ-002.10 | When | When the system places a file in the open project outside Save project, the system shall rewrite project.json with the carried records of the existing project.json. | Yes; tested (`test_tc_b100_20_variant_append_carries_every_key_and_activates`, `test_tc_b100_20_mac_sync_carries_every_key`, `test_tc_b100_20_a2l_sync_carries_every_key`, `test_tc_b100_20_save_back_carries_every_key`, `test_tc_b100_20_writers_carry_the_active_document`, `test_tc_b100_71_variant_append_carries_derived_from`, `test_tc_b100_28_variant_append_keeps_the_key`, `test_tc_b100_32_data_file_loaded_into_a2l_only_project_is_recorded`, `test_at_b100_20_every_writer_carries_the_keys_it_does_not_own`, `test_at_b100_20_inc8a_every_writer_carries_the_active_document`). D11-8 superseded by D11-59. |
| R-PROJ-002.11 | When | When the system has made a placed file the open project's active variant and rewritten project.json, the system shall show the status `Project '<project name>' now opens <file name>`. | Yes; tested (`test_tc_b100_20_append_says_now_opens_only_after_the_write`, `test_tc_b100_20_append_says_now_opens_only_after_the_write_on_any_platform`). |
| R-PROJ-002.12 | If | If the open project's folder cannot be read or no longer exists when the system adds an S19, Intel HEX or MAC file to it, then the system shall show the status `Project sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` | Partly: tested for a folder that cannot be read (`test_tc_b100_54_file_load_sync_refuses_when_the_project_folder_is_gone`); a folder deleted outside the app is re-created empty instead (D11-72; `app.py:14614-14630`). |
| R-PROJ-002.13 | If | If the open project's folder cannot be read or no longer exists when the system adds an A2L file to it, then the system shall show the status `A2L sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` | Partly: tested for a folder that cannot be read (`test_tc_b100_54_a2l_sync_refuses_when_the_project_folder_turns_unreadable`); a deleted folder is re-created empty instead (D11-72; `app.py:14737-14753`). |

#### Writes into the open project (from batch-100 HLR-168)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-WRITER.1 | If | If the open project's project.json has a rewrite refusal when the system places a file in the project outside Save project, then the system shall leave project.json unchanged. | Yes; tested (`test_tc_b100_20_damaged_manifest_is_never_rewritten`, `test_tc_b100_20_rewrite_never_drops_what_it_cannot_carry`). |
| R-PROJ-WRITER.2 | If | If the system leaves project.json unchanged for a rewrite refusal, then the system shall show the status `project.json in project '<project name>' <rewrite refusal> and was not rewritten - <file name> stays in the project; Save project rewrites it`. | Yes; untested (`app.py:14456-14468`). |
| R-PROJ-WRITER.3 | If | If the open project has no project.json when the system places a file in it, then the system shall write a new project.json. | Yes (`app.py:14455-14473`, ledger LED .67). |
| R-PROJ-WRITER.4 | U | The system shall write the integer 1 as schema_version and keep every other value of a rewritten project.json as it was read. | Yes; tested (`test_tc_b100_20_schema_version_is_the_integer_one`, `test_tc_b100_20_reader_keeps_a_float_schema_version`). |
| R-PROJ-SAVEBACK.1 | When | When a save-back (S8) writes an image into the open project, the system shall make that image's variant the active variant. | Yes; tested (`test_tc_b100_19_save_back_becomes_the_active_variant`, `test_at_b100_06_reopen_opens_the_saved_back_variant`). |
| R-PROJ-SAVEBACK.2 | When | When a save-back writes an image into the open project, the system shall record in derived_from the loaded image's file as the base of the written variant. | Yes; tested (`test_tc_b100_71_save_back_records_derived_from`). |
| R-PROJ-SAVEBACK.3 | If | If no project is open when a save-back writes an image, then the system shall write no project.json. | Yes; tested (`test_tc_b100_19_save_back_with_no_project_writes_no_manifest`). |

### S11.9 · Manifest: read (CTX-MANIFEST)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAR-002.1 | When | When the system loads a project or runs Execute scope, the system shall read the project's manifest. | Yes; tested (`test_load_project_honors_manifest_active_variant`). |
| R-VAR-002.2 | If | If the manifest is larger than the read cap, then the system shall record the finding MANIFEST-SIZE-CAP `the project manifest is <n> bytes, over the 1048576-byte read cap - the file was not loaded`. | Yes; tested (`test_tc_b100_24_one_byte_over_one_mib_is_size_cap`). The cap was 256 MiB at 093a7c0 (D11-57). |
| R-VAR-002.3 | If | If the manifest is not readable, well-formed JSON, then the system shall record the finding MANIFEST-JSON-PARSE `the project manifest is not readable well-formed JSON - ignored: <error type>`. | Yes; untested. |
| R-VAR-002.4 | If | If the manifest's top level is not a JSON object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `the project manifest top level is not a JSON object - ignored`. | Yes; untested. |
| R-VAR-002.5 | If | If the manifest is over the read cap, is not readable well-formed JSON or is not a JSON object, then the system shall read no key from it. | Yes; untested. |
| R-VAR-002.6 | If | If `schema_version` is neither a number nor a string, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest schema_version is neither a number nor a string`. | Yes; untested. |
| R-VAR-002.7 | U | The system shall read every manifest as version 1, whatever its `schema_version`. | Yes (D11-4). |
| R-VAR-002.8 | If | If `active_variant` is present and is not a string, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest active_variant is not a string - ignored`. | Yes; untested. |
| R-VAR-002.9 | If | If `batch` is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest batch is not an array - ignored`. | Yes; untested. |
| R-VAR-002.10 | If | If `assignments` is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest assignments is not an object - ignored`. | Yes; untested. |
| R-VAR-002.11 | If | If an `assignments` value is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest assignments['<variant id>'] is not an array - ignored`. | Yes; untested. |
| R-VAR-002.12 | If | If an entry is not a string or is blank, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest <context> entry is not a path string - entry skipped`. | Yes; untested. |
| R-VAR-002.13 | If | If an entry holds a NUL character, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry carries a NUL character - not a path; entry skipped: '<entry>'`. | Yes; tested through flow references (`tests/test_b97_flow_builder.py`). |
| R-VAR-002.14 | If | If an entry has a drive or a root, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry has a drive or a root - entry skipped: '<entry>'`. | Yes; tested (`test_manifest_containment_skips_unsafe_entries`, `test_tc_b100_60_reader_refuses_a_hostile_entry`). Was `... is an absolute path ...` at 093a7c0. |
| R-VAR-002.15 | If | If an entry resolves outside the project folder, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry escapes the project directory - entry skipped: '<entry>'`. | Yes; tested (`test_manifest_containment_skips_unsafe_entries`). |
| R-VAR-002.16 | If | If an entry passes through a link inside the project folder, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry traverses a symbolic link or reparse point - entry skipped: '<entry>'`. | Yes; untested. |
| R-VAR-002.17 | If | If a key or an entry gives a manifest finding, then the system shall read the other keys and entries. | Yes; tested (`test_manifest_containment_skips_unsafe_entries`). |
| R-VAR-002.18 | U | The system shall ignore manifest keys that CTX-MANIFEST does not list. | Yes. |
| R-VAR-002.19 | When | When the system reads the manifest, the system shall read the gathered entries as it reads batch entries. | Yes; tested (`test_tc_b100_18_valid_gathered_is_an_equal_dict`, `test_tc_b100_18_escaping_entry_is_one_issue_and_no_entry`). D11-5 superseded by D11-58. |

#### New keys and caps (from batch-100 HLR-168, HLR-169, HLR-170)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-MANIFEST-READ.1 | If | If gathered is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest gathered is not an object - ignored`. | Yes; tested (`test_tc_b100_18_list_instead_of_object_is_one_issue`). |
| R-MANIFEST-READ.2 | If | If a gathered value is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest gathered['<home>'] is not an array - ignored`. | Yes; tested (`test_tc_b100_18_home_value_not_a_list_is_one_issue`). |
| R-MANIFEST-READ.3 | If | If a key breaks the entry cap, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest <key> holds <n> entries, over the 1000-entry cap - defaults used`. | Yes; tested (`test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast`, `test_tc_b100_24_assignments_75_by_1000_is_one_issue_fast`, `test_tc_b100_24_exactly_the_cap_is_read`). |
| R-MANIFEST-READ.4 | If | If an entry is longer than 32 767 characters, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry is longer than 32767 characters - entry skipped`. | Yes; tested (`test_tc_b100_67_overlong_entries_are_skipped_rows_not_a_crash`, `test_tc_b100_67_overlong_entry_is_decided_on_the_text`). |
| R-MANIFEST-READ.5 | If | If an entry has more than 32 parts, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry has more than 32 path components - entry skipped`. | Yes; untested (`variant_execution_service.py:696-708`). |
| R-MANIFEST-READ.6 | If | If an entry holds a `:`, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry carries a ':' (a drive or a stream name) - entry skipped: '<entry>'`. | Yes; tested (`test_tc_b100_60_reader_refuses_a_hostile_entry`). |
| R-MANIFEST-READ.7 | If | If a part of an entry ends in a dot or a space, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry has a path component ending in a dot or a space: '<part>' - entry skipped: '<entry>'`. | Yes; tested (`test_tc_b100_60_reader_refuses_a_hostile_entry`). |
| R-MANIFEST-READ.8 | If | If a part of an entry is a device name, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry names a device: '<part>' - entry skipped: '<entry>'`. | Yes; tested (`test_tc_b100_60_reader_refuses_a_hostile_entry`, `test_tc_b100_60_reader_accepts_plain_entries`). |
| R-MANIFEST-READ.9 | If | If files is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest files is not an object - ignored`. | Yes; untested (`variant_execution_service.py:1270-1273`). |
| R-MANIFEST-READ.10 | If | If a files key names neither a recorded file of the project folder's top level nor the active document, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest files key is not a top-level data or A2L file - entry skipped: '<key>'`. | Yes; tested (`test_tc_b100_24_sub_folder_key_is_one_bad_structure`, `test_tc_b100_24_files_key_of_the_active_document_is_read`). |
| R-MANIFEST-READ.11 | If | If a files record has no whole-number size of at least 0 or no sha256 of 64 hex digits, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest files record is malformed - entry skipped: '<key>'`. | Yes; tested (`test_tc_b100_24_malformed_record_is_one_bad_structure`, `test_tc_b100_24_valid_record_is_one_record`). |
| R-MANIFEST-READ.12 | If | If derived_from is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest derived_from is not an object - ignored`. | Yes; untested (`variant_execution_service.py:1332-1335`). |
| R-MANIFEST-READ.13 | If | If a derived_from record is malformed, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest derived_from record is malformed - entry skipped: '<key>'`. | Yes; untested (`variant_execution_service.py:1350-1353`). |
| R-MANIFEST-READ.14 | If | If a derived_from base is not a plain file name, then the system shall record the finding `manifest derived_from base is not a plain file name - entry skipped: '<base>'`. | Yes; tested (`test_tc_b100_71_unsafe_base_is_one_issue_and_no_entry`, `test_tc_b100_24_derived_from_gets_no_document_exception`). |
| R-MANIFEST-READ.15 | If | If active_document is not a `.json` entry directly in `patches/` or `checks/`, then the system shall record the finding `manifest active_document is not a document in a project home - ignored: '<value>'`. | Yes; tested (`test_tc_b100_28_reader_refuses_a_value_out_of_form`, `test_tc_b100_28_form_predicate_refuses`, `test_tc_b100_28_cp1_form_refuses_device_stems_and_format_characters`). |
| R-MANIFEST-READ.16 | If | If gathered, files, derived_from or active_document is absent or null, then the system shall record no finding for it. | Yes; tested (`test_tc_b100_18_absent_key_is_empty_with_no_issue`, `test_tc_b100_28_reader_null_and_absent_are_none`). |
| R-MANIFEST-READ.17 | If | If a read skips more entries than the finding bound, then the system shall record one finding `<n> more manifest entries were skipped` for the rest. | Yes; tested (`test_tc_b100_61_skipped_entries_beyond_the_bound_are_counted`). |

### S11.10 · Manifest: write and verify

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-MAN-SER-001.1 | When | When the system writes the manifest, the system shall write the keys of CTX-MANIFEST in their listed order. | Yes; tested (`test_envelope_keys_and_active_variant`, `test_tc_b100_28_writer_and_reader_round_trip`). |
| R-MAN-SER-001.2 | When | When the system writes the manifest, the system shall write `schema_version` as 1. | Yes; tested (`test_roundtrip_schema_version_survives`). |
| R-MAN-SER-001.3 | When | When the system writes the manifest, the system shall write `active_variant` as the active variant's id, or null when the project has no variant. | Yes; tested (`test_envelope_empty_project_active_variant_is_null`). |
| R-MAN-SER-001.4 | When | When the system writes an entry, the system shall write it with `/` as separator. | Yes; tested (`test_windows_backslashes_normalized_to_forward_slash`). |
| R-MAN-SER-001.5 | U | The system shall write the same manifest bytes for the same project content. | Yes; tested (`test_deterministic_byte_identical_output`). |
| R-MAN-SER-001.6 | U | The system shall write a manifest that reads back with the written values and no manifest finding. | Yes; tested (`test_roundtrip_equals_intent_in_canonical_form`). |
| R-MAN-SER-001.7 | If | If any entry to write is an unsafe entry, then the system shall write no manifest. | Yes; tested (`test_refuse_escape_and_absolute_entries_writes_nothing`, `test_tc_b100_28_writer_refusal_writes_no_bytes`, `test_tc_b100_28_writer_refuses_a_junction_home`). |
| R-MAN-SER-001.8 | If | If an entry to write is an unsafe entry, then the system shall record the finding MANIFEST-WRITE-ESCAPE `refusing to serialize manifest <context> entry that is absolute or escapes the project directory: '<entry>'`. | Yes; tested (`test_refuse_escape_and_absolute_entries_writes_nothing`). |
| R-MAN-SER-001.9 | If | If the last save gathered no file, then the system shall leave `gathered` out of the manifest. | Yes. |
| R-MAN-SER-001.10 | When | When the save has gathered files, the system shall write `gathered` as the sorted entries of each project home that received a file. | Yes. |
| R-MANIFEST-WRITE.1 | When | When the system writes gathered for a merge or a save as, the system shall write per home the sorted union of the carried entries and the entries this save gathered. | Yes; tested (`test_tc_b100_05_merge_carries_the_document_and_gathered`); a save into the open project writes only this save's entries (`test_tc_b100_05_r13_open_project_save_does_not_carry_gathered`). |
| R-MANIFEST-WRITE.2 | When | When the system writes the manifest, the system shall write files with the size and the SHA-256 of every recorded file as it is on disk after every file of the write has landed. | Yes; tested (`test_tc_b100_21_save_records_every_file_digest`, `test_tc_b100_21_zero_byte_file_and_round_trip`, `test_tc_b100_22_seam_scope_is_top_level_data_and_a2l`, `test_tc_b100_28_a15_files_records_the_active_document`). |
| R-MANIFEST-WRITE.3 | If | If no file is recorded, then the system shall leave files out of the manifest. | Yes; tested (`test_tc_b100_21_no_files_is_byte_identical`, `test_tc_b100_28_a15_absent_document_has_no_record`). |
| R-MANIFEST-WRITE.4 | If | If no derived_from record is set, then the system shall leave derived_from out of the manifest. | Yes; tested (`test_tc_b100_71_byte_copy_records_nothing`). |
| R-MANIFEST-WRITE.5 | If | If no active document is recorded, then the system shall leave active_document out of the manifest. | Yes; tested (`test_tc_b100_28_absent_key_is_byte_identical`). |
| R-MANIFEST-WRITE.6 | If | If the active_document to write is not a `.json` entry directly in `patches/` or `checks/`, then the system shall record the finding MANIFEST-WRITE-ESCAPE `refusing to serialize manifest active_document that is not a .json file directly in patches/ or checks/: '<value>'`. | Yes; tested (`test_tc_b100_28_writer_refuses_a_value_out_of_form`, `test_tc_b100_28_form_predicate_accepts`, `test_tc_b100_28_form_predicate_is_total`). |
| R-MANIFEST-WRITE.7 | If | If a files key to write names neither a top-level file nor the active document, then the system shall record the finding MANIFEST-WRITE-ESCAPE `refusing to serialize manifest files key that is neither a top-level file nor the active document: '<key>'`. | Yes; tested (`test_tc_b100_28_writer_refuses_a_sub_folder_files_key_unless_it_is_the_document`). |
| R-MAN-WRITE-001.1 | When | When the system writes the manifest, the system shall write it to `<project folder>/project.json` in place of any earlier one. | Yes; tested (`test_two_saves_leave_exactly_one_manifest_second_wins`). |
| R-MAN-WRITE-001.2 | U | The system shall never write the manifest under a numbered name. | Yes; tested (`test_fixed_name_and_staged_temp_removed`). |
| R-MAN-WRITE-001.3 | When | When the system writes the manifest, the system shall leave no half-written project.json. | Yes; untested. |
| R-MAN-WRITE-001.4 | When | When the system writes the manifest, the system shall change no other file of the work area. | Yes; tested (`test_tc_b100_27_concurrent_manifest_writes`). D11-36 settled by batch-100 Inc 7 (private staging, `manifest_writer.py:640-656`). |
| R-MAN-WRITE-001.5 | If | If project.json is outside the work area or passes through a link, then the system shall record the finding MANIFEST-WRITE-CONTAINMENT `the manifest write target failed work-area containment validation — no file was written`. | Yes; tested (`test_destination_outside_workarea_returns_finding`, `test_tc_b100_62_manifest_write_refuses_a_project_swapped_for_a_junction`). The error type and reason moved from the message to the finding's details (`manifest_writer.py:653-661`); the shared guard reads the unresolved path (`manifest_writer.py:490-523`). D11-36 settled. |
| R-MAN-WRITE-001.6 | If | If writing project.json fails with an operating-system error, then the system shall record the finding MANIFEST-WRITE-CONTAINMENT of R-MAN-WRITE-001.5. | Yes; untested (`manifest_writer.py:652-661`). |
| R-MANIFEST-WRITE.8 | If | If project.json lands outside the work area because the project folder changed during the write, then the system shall record the finding MANIFEST-WRITE-CONTAINMENT `the project folder changed during the manifest write - project.json landed outside this work area at <path>`. | Yes; tested (`test_tc_b100_62_swap_after_the_check_is_reported_never_written`, `test_tc_b100_62_swap_toast_and_status_paint_no_exception_class`). |
| R-MAN-TUI-001.1 | If | If the system cannot write the manifest, then the system shall show the status `Manifest write failed`. | Yes; tested (`test_manifest_write_refusal_surfaces_error_notice_no_crash`). |
| R-MAN-TUI-001.2 | If | If the system cannot write the manifest, then the system shall show an error notice titled `Manifest write failed - project.json not written` with the finding messages joined by `; `. | Yes; tested (`test_manifest_write_refusal_surfaces_error_notice_no_crash`). |
| R-MAN-TUI-001.3 | If | If the system cannot write the manifest, then the system shall refuse the whole save (S11.5). | Yes; tested (`test_tc_b100_17_failed_manifest_write_adopts_nothing`). |
| R-MAN-VERIFY-001.1 | When | When the system has written the manifest, the system shall read it back from `<project folder>/project.json`. | Yes; tested (`test_verify_reads_canonical_name_not_a_stray_suffixed_file`). |
| R-MAN-VERIFY-001.2 | If | If the read-back active_variant, batch, assignments, files, derived_from or active_document differ from what the system wrote, or the read-back gives a manifest finding, then the system shall report a verify mismatch. | Yes; tested (`test_tampered_active_variant_mismatches_naming_the_key`, `test_reader_issues_force_mismatch_even_if_surviving_keys_match`, `test_tc_b100_23_digest_changed_between_write_and_verify`, `test_tc_b100_23_derived_from_count_changed_is_one_mismatch`, `test_tc_b100_23_active_document_changed_between_write_and_verify`, `test_tc_b100_23_unchanged_is_verified`). |
| R-MAN-VERIFY-001.3 | If | If the read-back declared_regions or gathered differ from what the system wrote, then the system shall report a verify mismatch. | No: neither key is compared (D11-35; re-verified `manifest_writer.py:895-910`). |
| R-MAN-VERIFY-001.4 | If | If the read-back manifest equals what the system wrote, then the system shall show the status `Project saved + manifest verified`. | Yes; tested (`test_project_save_writes_and_verifies_manifest`). |
| R-MAN-VERIFY-001.5 | If | If the system reports a verify mismatch, then the system shall show an error notice titled `Manifest verify mismatch - project.json may be wrong` with the text `drift: <differing keys>; <finding messages>`. | Yes; tested (`test_manifest_mismatch_surfaces_loud_notice_naming_drift`). |
| R-MAN-VERIFY-001.6 | If | If the system reports a verify mismatch, then the system shall show `Manifest verify MISMATCH` as the newest status line, after the save status. | Yes; tested (`test_tc_b100_07_manifest_mismatch_is_the_newest_status_line`). |
| R-MAN-VERIFY-001.7 | If | If the system reports a verify mismatch, then the system shall keep the save. | Yes (D11-6). |
| R-MAN-VERIFY-001.8 | U | The system shall show finding messages in manifest notices as plain text, never as markup. | Yes; untested. |
| R-MANIFEST-VERIFY.1 | When | When a rewrite of project.json outside Save project reads back equal to what the system wrote, the system shall show the status `project.json updated + verified`. | No: shows `Project saved + manifest verified` although no project was saved (D11-71; `app.py:12976-12979`). |

#### Keeping a project.json this version cannot rewrite (from batch-100 HLR-169)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-MANIFEST-KEEP.1 | If | If the target's project.json has a keep reason, then the system shall keep its content under the backup name before it writes the new project.json. | Yes; tested (`test_tc_b100_07_save_project_keeps_a_manifest_it_cannot_carry`, `test_tc_b100_07_taken_previous_names_move_to_the_next_candidate`, `test_tc_b100_07_previous_copy_never_lands_outside_the_work_area`). |
| R-MANIFEST-KEEP.2 | If | If the system keeps the previous project.json, then the system shall show the status `project.json <keep reason>: its previous content is kept as <backup name> in <project folder>`. | Yes; untested (`app.py:11946-11949`). |
| R-MANIFEST-KEEP.3 | If | If the previous content cannot be kept, then the system shall refuse the save with the status `Project NOT saved: project.json <keep reason> and its content could not be kept beside it in <project folder>`. | Yes; tested (`test_tc_b100_07_save_project_refuses_when_no_previous_copy_can_be_kept`). |
| R-MANIFEST-KEEP.4 | If | If the save completes, then the system shall remove no backup it kept. | Yes; tested (`test_tc_b100_07_rollback_keeps_the_previous_copy_unless_restored`). |
| R-MANIFEST-KEEP.5 | If | If the kept project.json recorded a change document path this version cannot use, then the system shall show the status `Change document record <entry> was dropped from project.json — its previous content is kept as <backup name>`. | Yes; untested (`app.py:11950-11963`). |

### S11.11 · Composition in the Save dialog

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJ-ASSIGN-UI-001.1 | When | When the Save dialog opens for an open project with variants and project documents, the system shall show the batch list and one assignment list per variant. | Yes; tested (`test_tc304_screen_collects_per_variant_and_batch_assignment`). |
| R-PROJ-ASSIGN-UI-001.2 | When | When the Save dialog opens with no open project, the system shall show no batch or assignment list. | Yes. |
| R-PROJ-ASSIGN-UI-001.3 | When | When the Save dialog shows the lists, the system shall offer in each list the open project's project documents. | Partly: only `.json` files directly in the project folder; `patches/` and `checks/` are never offered (D11-23; re-verified `app.py:8064-8098`). |
| R-PROJ-ASSIGN-UI-001.4 | When | When the Save dialog shows the lists, the system shall leave project.json out of them. | Yes; tested (`test_tc305_screen_offers_only_in_project_candidate_files`). |
| R-PROJ-ASSIGN-UI-001.5 | When | When the Save dialog shows the lists, the system shall select in them the documents the manifest already names. | No: nothing is selected (D11-24; `screens.py:1037-1066`); since batch-100 a save with nothing selected keeps the recorded composition (R-PROJ-ASSIGN-001.5, .6). |
| R-PROJ-ASSIGN-UI-001.6 | U | The system shall show folder, file and variant names in the Save dialog as plain text, never as markup. | Yes; tested (`test_tc_b100_65_names_are_painted_literally`, `test_tc_b100_65_assignment_rows_literal_and_in_the_tab_order`). The Load dialog's rows and the Select variant dialog are S7's (S7 R-DLG.13; D11-38). |
| R-PROJ-ASSIGN-001.1 | When | When the system saves a project, the system shall write the documents selected in the batch list as `batch`. | Yes; tested (`test_at017_1_save_persists_and_round_trips_composition`). |
| R-PROJ-ASSIGN-001.2 | When | When the system saves a project, the system shall write the documents selected for each variant as that variant's `assignments` list. | Yes; tested (`test_at017_1_save_persists_and_round_trips_composition`). |
| R-PROJ-ASSIGN-001.3 | When | When the system writes `assignments`, the system shall key each list by the variant id. | Yes; tested (`test_at017_5_stem_collision_assignment_keyed_by_full_filename`). |
| R-PROJ-ASSIGN-001.4 | If | If a variant has no selected document, then the system shall leave the variant out of `assignments`. | Yes; tested (`test_tc304_screen_collects_per_variant_and_batch_assignment`). |
| R-PROJ-ASSIGN-001.5 | If | If no document is selected in the batch list, then the system shall write as batch the carried batch of the target, or an empty array when there is none. | Yes; tested (`test_tc_b100_31_empty_selection_keeps_batch_for_every_target`, `test_at017_3_zero_selection_save_no_regression`). Was "write the composition empty" (D11-60). |
| R-PROJ-ASSIGN-001.6 | If | If no document is selected for any variant, then the system shall write as assignments the carried assignments of the target, or an empty object when there are none. | Yes; tested (`test_tc_b100_31_empty_selection_keeps_batch_for_every_target`). |
| R-PROJ-ASSIGN-001.7 | When | When the system gathers composition documents, the system shall take their names from the batch and the assignments it writes. | Yes; tested (`test_tc_b100_31_gather_takes_names_from_the_recorded_batch_and_assignments`). |
| R-PROJ-ASSIGN-SEC-001.1 | If | If a selected document is an unsafe entry, then the system shall refuse the whole save. | Yes; tested (`test_at017_4_escaping_assignment_refused_no_file_written`). |

### S11.12 · Declared regions in the manifest

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RPT-REGION-PERSIST-001.1 | When | When the operator presses Generate in the Reports dialog (S12), the system shall keep the dialog's declared regions for the next project save. | Yes; tested (`test_save_persists_declared_regions`). Exception while a session action runs: S12 R-RPT-002.28 (LLR-177.3i). |
| R-RPT-REGION-PERSIST-001.2 | If | If the operator closes the Reports dialog without Generate, then the system shall keep the regions it kept before. | Yes; tested (`test_typed_but_not_generated_not_saved`). |
| R-RPT-REGION-PERSIST-001.3 | When | When the system saves a project, the system shall write the kept regions as `declared_regions`. | Yes; tested (`test_save_persists_declared_regions`). |
| R-RPT-ADDENDUM-PERSIST-001.1 | If | If no region is kept, then the system shall leave `declared_regions` out of the manifest. | Yes; tested (`test_serialize_omits_declared_regions_key_when_empty`, `test_save_without_regions_byte_identical`). |
| R-RPT-ADDENDUM-PERSIST-001.2 | If | If the manifest has no `declared_regions` key, then the system shall read no declared region. | Yes; tested (`test_read_absent_key_empty_and_malformed_collected`). |
| R-RPT-ADDENDUM-PERSIST-001.3 | If | If `declared_regions` is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest declared_regions is not an array - ignored`. | Yes; untested. |
| R-RPT-ADDENDUM-PERSIST-001.4 | If | If a `declared_regions` entry is not an object with a text `name` and whole-number `start` and `end`, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest declared_regions entry is malformed - ignored: <entry>`. | Yes; tested (`test_read_absent_key_empty_and_malformed_collected`). |
| R-RPT-ADDENDUM-PERSIST-001.5 | If | If a `declared_regions` entry breaks the region rules, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest declared_regions entry is invalid - ignored: <entry>`. | Yes; untested. |
| R-RPT-ADDENDUM-PERSIST-001.6 | When | When the system reads a declared region, the system shall remove control characters and terminal escape sequences from its name. | Yes; tested (`test_read_absent_key_empty_and_malformed_collected`). |
| R-RPT-ADDENDUM-PERSIST-001.7 | If | If a declared region's name is longer than 80 characters, then the system shall cut it to 80 characters ending in `…[truncated]`. | Yes; untested. |
| R-RPT-REGION-PERSIST-002.1 | When | When the system loads a project, the system shall keep the manifest's declared regions for the Reports dialog. | Yes; tested (`test_load_sets_declared_regions_state`, `test_tc_b100_46_project_load_adopts_declared_regions_after_the_reset`: kept after the reset of a load confirmed in the load question). |
| R-RPT-REGION-PERSIST-002.2 | If | If the loaded project's manifest declares no region, then the system shall keep no declared region. | Yes; tested (`test_load_seed_guard`). |
| R-RPT-REGION-PERSIST-002.3 | When | When the operator opens the Reports dialog, the system shall fill its region box with one line `<name>,<start>,<end>` per kept region. | Yes; tested (`test_load_prefills_declared_regions`). Start and end are written in decimal (D11-41, prototype first). |

### S11.13 · Executing over variants (CTX-EXEC)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-VAR-002.20 | If | If no project with variants is open when the operator runs Execute scope, then the system shall show the status `Execute: no project variants - load a project first.` | Yes; tested (`test_execute_scope_without_project_is_status_error`). |
| R-VAR-002.21 | If | If neither the manifest nor the Patch Editor names a document when the operator runs Execute scope, then the system shall show the status `Execute: no manifest and no loaded change/check file - nothing to execute.` | Partly: given only when there is no manifest; with a manifest that names no file the run starts and runs nothing (D11-25). |
| R-VAR-002.22 | If | If the project folder breaks rule R-TUI-014.1 or R-TUI-014.2 when the operator runs Execute scope, then the system shall refuse the run with that rule's status. | No: the run goes on with neither MAC nor A2L, without a message (D11-39). |
| R-VAR-002.23 | When | When a run starts, the system shall show the status `Execute: scope '<scope>' started...`. | Yes. |
| R-VAR-002.24 | When | When the operator runs Execute scope, the system shall run the file list of each in-scope variant, variants in variant order. | Partly: with a manifest that names no file the Patch Editor's document is not used (D11-25); order tested (`test_double_run_orderings_identical`, `test_manifest_absent_defaults_to_batch_all`). |
| R-VAR-002.25 | When | When the system runs a variant, the system shall read the variant's image from its file in the project folder. | Yes (D11-10). |
| R-VAR-002.26 | When | When the system runs a variant, the system shall leave the session's image unchanged. | Yes. |
| R-VAR-002.27 | When | When the system runs a variant, the system shall use the project's MAC and A2L files. | Yes. |
| R-VAR-002.28 | When | When the system runs a document whose kind is check, the system shall run its checks (S9). | Yes. |
| R-VAR-002.29 | When | When the system runs a document of any other kind, the system shall apply it as a change document (S8). | Yes. |
| R-VAR-002.30 | When | When the system runs a document on a variant, the system shall mark its results with the variant id. | Yes; tested (`test_batch_execution_stamps_variant_ids`). |
| R-VAR-002.31 | If | If a change document applies at least one entry to an S19 variant, then the system shall save the patched variant in the project folder under the patched name. | Yes; tested (`test_save_back_files_land_under_project_dir`). |
| R-VAR-002.32 | If | If a change document applies at least one entry to an Intel HEX variant, then the system shall save the patched variant in the project folder under the patched name. | No: shows `HEX save-back not supported this batch - patched image not persisted` (D11-32). |
| R-VAR-002.33 | When | When the system saves a patched S19 variant, the system shall keep the variant's S0 header. | No: an empty S0 is written (D11-33). |
| R-VAR-002.43 | When | When the system saves a patched S19 variant whose source has a terminator, the system shall write the address of the source's terminator in the terminator. | No: address 0 is written (D11-42). |
| R-VAR-002.34 | If | If one variant fails, then the system shall run the remaining variants. | Yes; tested (`test_failing_variant_never_aborts_the_rest`). |
| R-VAR-002.35 | When | When a variant starts, the system shall show the status `Executing variant '<variant id>' (<n> file(s))...`. | Yes. |
| R-VAR-002.36 | When | When a variant ends, the system shall show the status `Variant '<variant id>': <ok or error> - <c> change, <k> check` once. | Partly: shown twice, once when the variant ends and once in the final report (D11-34). |
| R-VAR-002.37 | When | When a variant ends with diagnostics, the system shall show each as `Variant '<variant id>': <diagnostic>`. | Yes. |
| R-VAR-002.38 | When | When the run ends, the system shall show each manifest finding as a finding line before the variant lines. | Yes. |
| R-VAR-002.39 | When | When the run ends, the system shall show the status `Execute: scope '<scope>' finished - <n> variant(s), <e> error(s)`. | Yes. |
| R-VAR-002.40 | If | If reading the project's MAC or A2L file, or any other error, stops the run, then the system shall show the status `Execute failed: <error type>: <reason>`. | Yes. |
| R-VAR-002.41 | U | The system shall keep the screen responsive while it runs Execute scope. | Yes. |
| R-VAR-002.42 | When | When an Execute scope run ends, the system shall keep its results, with the project folder, as the kept execution of S12 CTX-RPT-RUN. | Yes; tested (`test_execution_report_retains_results`; `app.py:4730`). The project session reset drops it (`app.py:9823`). |
| R-PROJ-EXEC.1 | When | When an Execute scope run has saved a patched variant into the project, the system shall rewrite project.json with the carried records. | No: the run writes `<variant id>-patched.s19` but no project.json, so the next load lists the file as `not recorded` (D11-70; `variant_execution_service.py:2581-2588`). |

### S11.14 · Save as (from batch-100 HLR-171; CTX-SAVE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-SAVEAS-1 | When | When the system saves as, the system shall copy each regular file of the open project that the save does not write itself, at the top level and at every depth of its sub-folders, to the same path in the new project folder. | Yes; tested (`test_tc_b100_31_save_as_copies_every_subfolder_file`, `test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups`, `test_tc_b100_31_save_as_with_no_subfolder_copies_none`, `test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow`). |
| R-SAVEAS-2 | When | When the system saves as, the system shall copy no backup of project.json. | Yes; tested (`test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups`). |
| R-SAVEAS-3 | When | When the system saves as, the system shall copy no file reached through a link or junction. | Yes; tested (`test_tc_b100_31_links_are_skipped_and_named`, `test_tc_b100_31_junction_cycle_ends`). |
| R-SAVEAS-4 | If | If a save as skips links or junctions, then the system shall show, after the save status, the status `Save as: links or junctions not copied: <painted list> — copy those files into the project if it needs them.` | Yes; tested (`test_tc_b100_31_links_are_skipped_and_named`, `test_tc_b100_31_link_line_names_at_most_ten`, `test_tc_b100_31_link_names_are_scrubbed`, `test_tc_b100_31_painted_names_clip_scrub_and_count`). |
| R-SAVEAS-5 | When | When the system saves as, the system shall leave every file of the open project unchanged. | Yes; tested (`test_tc_b100_31_save_as_copies_every_subfolder_file`). |
| R-SAVEAS-6 | When | When the system saves as, the system shall write into the new project.json the carried records of the open project. | Yes; tested (`test_tc_b100_31_save_as_carries_the_open_projects_records`). |
| R-SAVEAS-7 | If | If the open project's project.json is a link, then the system shall carry no record from it into the new project. | Yes; tested (`test_tc_b100_31_linked_project_json_is_not_carried`). |
| R-SAVEAS-8 | When | When a save as completes, the system shall make the new project folder the Flow panels' session folder. | Yes; tested (`test_tc_b100_31_flow_session_folder_follows_q`). |
| R-SAVEAS-9 | When | When a save as completes, the system shall bind a Patch Editor document whose file lies in the previous project folder to that file's copy in the new project folder. | Yes; tested (`test_e4_llr_171_1m_document_inside_p_follows_its_copy`, `test_tc_b100_31_document_with_an_identical_sibling_follows_its_landing`). |
| R-SAVEAS-10 | If | If the open project's folder no longer exists when the system saves to a new folder, then the system shall save the session's files without a copy from the open project. | Yes; tested (`test_tc_b100_31_open_project_folder_gone_saves_without_a_copy`, `test_tc_b100_65_vanished_source_after_a_save_as_preview_copies_nothing`). |
| R-SAVEAS-11 | If | If the open project's folder no longer exists when the system saves to a new folder, then the system shall show, after the save status, the status `The open project folder '<painted folder name>' was not found — its other files were not copied; copy them into '<painted clean name>' if you still have them.` | Yes; tested (`test_tc_b100_31_open_project_folder_gone_saves_without_a_copy`). |
| R-SAVEAS-12 | If | If a folder from the work area down to a file the save as copies is a link when the system reads that file, then the system shall refuse the save with the status `Project NOT saved: could not save — <painted path> changed while saving — check the folder.` | Yes; tested (`test_tc_b100_31_copy_refuses_when_p_itself_becomes_a_junction`). |
| R-SAVEAS-13 | If | If a save-as copy fails after the project folder exists, then the system shall refuse the save with the status `Project NOT saved: could not save — <painted path> could not be copied — check the folder.` | Yes; tested (`test_tc_b100_31_failed_copy_rolls_back_in_user_terms`). |
| R-SAVEAS-14 | If | If a top-level file of a save as lands at another name than its plan row because the new project already holds the same bytes, then the system shall refuse the save with the status `Project NOT saved: the plan named <name> (<action word>) but the file landed at <name> (<action word>) — <landed name> already holds the same bytes as <name> — remove the duplicate copy from the open project folder '<painted folder name>', then save again.` | Yes; tested (`test_tc_b100_31_identical_copy_mismatch_names_a_true_step`). |

### S11.15 · Load result: problems (from batch-100 HLR-169; CTX-LOADRES)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PROJCHK-1 | When | When the system loads a project, the system shall check every recorded file of project.json against the project folder. | Yes; tested (`test_tc_b100_25_check_reports_each_case`, `test_tc_b100_25_load_reports_the_case`). |
| R-PROJCHK-2 | If | If the project has no project.json, then the system shall list a `no project.json` problem for project.json. | Yes; tested (`test_tc_b100_55_first_by_name_no_project_json`). |
| R-PROJCHK-3 | If | If project.json is a damaged manifest, then the system shall list a `manifest damaged` problem with the reason of the first finding. | Yes; tested (`test_tc_b100_61_case_7_is_only_manifest_damaged`, `test_tc_b100_67_integer_over_the_digit_limit_reads_as_damaged`). |
| R-PROJCHK-4 | If | If a recorded file is absent, then the system shall list a `missing` problem with the reason `recorded in project.json, not on disk`. | Yes; tested (`test_tc_b100_25_missing_active_document_is_one_problem`, `test_tc_b100_25_missing_document_survives_the_no_digests_return`, `test_tc_b100_30_missing_document_is_one_missing_problem`). |
| R-PROJCHK-5 | If | If a recorded file is not a regular file or cannot be read, then the system shall list a `not readable` problem with the reason `not a regular file` or `the file cannot be read`. | Yes; tested (`test_tc_b100_25_unreadable_file_is_one_problem_never_a_raise`, `test_tc_b100_25_recorded_device_name_is_not_readable`). |
| R-PROJCHK-6 | If | If a recorded file's size differs from its record, then the system shall list a `changed on disk` problem with the reason `saved <n> B, now <m> B`. | Yes; tested (`test_tc_b100_61_changed_and_unrecorded_is_changed_on_disk`). |
| R-PROJCHK-7 | If | If a recorded file has its recorded size and another SHA-256, then the system shall list a `changed on disk` problem with the reason `same size (<n> B), different content`. | Yes; tested (`test_at_b100_07_load_names_the_changed_file_and_the_hostile_record`, `test_tc_b100_25_changed_document_is_named_by_its_project_text`). |
| R-PROJCHK-8 | If | If a project file with a data or A2L suffix directly in the project folder has no files record, then the system shall list a `not recorded` problem with the reason `in the project, not in project.json`. | Yes; tested (`test_tc_b100_25_check_reports_each_case`). |
| R-PROJCHK-9 | If | If project.json is not damaged and records no files, then the system shall list a `no digests saved` problem for project.json. | Yes; tested (`test_tc_b100_25_check_reports_each_case`). |
| R-PROJCHK-10 | If | If a variant file does not read as an S19 or Intel HEX image, then the system shall list a `not readable` problem with the reason `not an S19 or HEX file`. | Yes; tested (`test_tc_b100_61_case_6_is_only_not_readable`). |
| R-PROJCHK-11 | If | If a variant file reads without errors and holds no data byte, then the system shall list a `not readable` problem with the reason `0 data bytes`. | Yes; tested (`test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on`). |
| R-PROJCHK-12 | If | If a variant file reads with diagnostics and holds at least one data byte, then the system shall open it. | Yes; tested (`test_tc_b100_61_checksum_errors_only_keep_the_image_open`). |
| R-PROJCHK-13 | If | If the recorded variant is not a variant of the project, then the system shall list a `missing` problem for its file with the reason `recorded as the active variant`. | Yes; tested (`test_tc_b100_55_next_valid_when_the_recorded_one_is_missing`, `test_tc_b100_25_r7_missing_variant_never_names_the_document`). |
| R-PROJCHK-14 | If | If one file has more than one problem, then the system shall list only its problem of highest precedence. | Yes; tested (`test_tc_b100_61_case_6_is_only_not_readable`, `test_tc_b100_55_composer_adds_no_second_copy_of_the_check`). |
| R-PROJCHK-15 | U | The system shall list the problems of a project load in precedence order. | Yes; tested (`test_tc_b100_55_three_problems_in_precedence_order`). |
| R-PROJCHK-16 | If | If a project load finds problems, then the system shall open every project file that reads. | Yes; tested (`test_at_b100_07_load_names_the_changed_file_and_the_hostile_record`, `test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second`). |
| R-PROJCHK-17 | U | The system shall write the issue codes and exception class names of a project load to the log only. | Yes; tested (`test_tc_b100_61_seven_kinds_seven_next_steps_no_codes`, `test_tc_b100_67_damaged_manifest_paints_user_terms_only`). |
| R-PROJCHK-18 | U | The system shall give each problem the next step of CTX-LOADRES. | Yes; tested (`test_tc_b100_61_seven_kinds_seven_next_steps_no_codes`, `test_tc_b100_30_not_readable_document_paints_the_next_step_of_its_reason`, `test_tc_b100_30_cp1_next_step_follows_the_mark_not_the_reason_text`). |

### S11.16 · Load result: status and panel (from batch-100 HLR-178; CTX-LOADRES)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LOADRES-1 | If | If the summary line is longer than 118 characters, then the system shall shorten the load target, then the project name, each to no fewer than 8 characters ending in `…`. | Yes; tested (`test_tc_b100_56_long_names_keep_the_details_key_inside_118_columns`). |
| R-LOADRES-2 | When | When a project load that the operator started from the Load dialog completes, the system shall open the Load-result panel. | Yes; tested (`test_tc_b100_67_focus_starts_on_the_list_and_enter_keeps_it_open`, `test_tc_b100_53_load_result_panel_opens_after_the_install`, `test_tc_b100_40_project_choice_opens_the_load_result_panel`, `test_at_b100_19_the_panel_names_the_opened_variant_and_why`). No panel after a confirmed quit (S6 R-QUIT). |
| R-LOADRES-3 | When | When the Load-result panel opens, the system shall show the title, the summary grid, the heading and the problem rows of CTX-LOADRES. | Yes; tested (`test_at_b100_19_the_panel_names_the_opened_variant_and_why`, `test_tc_b100_67_thirty_problems_all_rows_and_end_reaches_the_last`, `test_tc_b100_67_wrapped_lines_hang_under_their_column`). |
| R-LOADRES-4 | When | When the system composes the result of a project load, the system shall give the load reason that applies. | Yes; tested (`test_tc_b100_55_recorded_active`, `test_tc_b100_55_first_by_name_none_recorded`, `test_tc_b100_55_first_by_name_manifest_damaged`, `test_tc_b100_55_five_reasons_have_distinct_user_text`, `test_tc_b100_55_boundaries_one_variant_and_no_image`). |
| R-LOADRES-5 | If | If derived_from records the opened variant, then the system shall show the relation line. | Yes; tested (`test_tc_b100_55_patched_line_names_the_recorded_base_not_the_first_by_name`, `test_tc_b100_55_patched_line_when_the_base_is_not_in_the_project`, `test_tc_b100_55_no_record_no_relation`). |
| R-LOADRES-6 | U | The system shall call a variant the latest saved only when it is the recorded variant. | Yes; tested (`test_tc_b100_55_latest_never_comes_from_file_times`). |
| R-LOADRES-7 | If | If more problems are found than the problem bound, then the system shall list the first 102 and one row that counts the rest. | Yes; untested (`variant_execution_service.py:2301-2320`; D11-54). |
| R-LOADRES-8 | When | When the Load-result panel opens, the system shall put the focus on the problem list. | Yes; tested (`test_tc_b100_67_focus_starts_on_the_list_and_enter_keeps_it_open`). |
| R-LOADRES-9 | When | When the operator presses tab in the Load-result panel, the system shall move the focus to Close. | Yes; tested (`test_tc_b100_67_tab_reaches_close_and_enter_closes`). |
| R-LOADRES-10 | When | When the operator presses escape in the Load-result panel or Enter on Close, the system shall close the panel. | Yes; tested (`test_tc_b100_67_the_shown_esc_key_closes_it`, `test_tc_b100_67_tab_reaches_close_and_enter_closes`). |
| R-LOADRES-11 | When | When the operator presses v in the Load-result panel, the system shall open the Select variant dialog in place of the panel. | Yes; tested (`test_tc_b100_67_v_opens_the_variant_selector`). |
| R-LOADRES-12 | U | The system shall let the operator scroll the problem list to its last row with the keyboard alone. | Yes; tested (`test_tc_b100_67_thirty_problems_all_rows_and_end_reaches_the_last`). |
| R-LOADRES-13 | U | The system shall show names in the Load-result panel, the file status and the summary line as plain text, never as markup. | Yes; tested (`test_tc_b100_56_hostile_variant_name_paints_no_markup`, `test_tc_b100_56_recorded_variant_with_control_bytes_paints_none`). |
| R-LOADRES-14 | If | If the opened variant is the recorded variant, then the system shall paint the load reason in the OK colour (S3 CTX-LEGEND). | Yes; tested (`test_tc_b100_67_recorded_reason_paints_in_the_ok_colour`). |
| R-LOADRES-15 | If | If the opened variant is not the recorded variant, then the system shall paint the load reason in the warning colour (S3 CTX-LEGEND). | Yes; tested (`test_tc_b100_67_fallback_and_problems_paint_in_the_warning_colour`). |
| R-LOADRES-16 | U | The system shall paint the mark and the problem word of each problem row in the warning colour (S3 CTX-LEGEND). | Yes; tested (`test_tc_b100_67_fallback_and_problems_paint_in_the_warning_colour`). |
| R-LOADRES-17 | If | If a manifest entry cannot be checked because it is too long or loops through a junction, then the system shall list it as a skipped row and go on with the load. | Yes; tested (`test_tc_b100_67_overlong_entries_are_skipped_rows_not_a_crash`, `test_tc_b100_67_junction_loop_entry_is_a_skipped_row_not_a_crash`). |
| R-LOADRES-18 | If | If a variant of the project did not read during the load, then the system shall follow its name in the Others list of the Load-result panel with `   not readable`. | Yes; tested (`test_tc_b100_64_a_load_that_installs_another_variant_names_it`). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D11-1 | The chapter carries batch history, HLR/LLR/TC ids, test counts, the §17 design note on where the writer lives, and "Status" / "Validation" narratives. | Out of the requirements; they stay in the batch records. |
| D11-2 | R-TUI-014 still says "at most one S19/HEX file"; the code accepts any number of variants (`workspace.py:1876-1893`). | Rows follow the code (R-TUI-014.1 … .3). |
| D11-3 | R-VAR-001/002 and R-MAN-* prescribe dataclasses, function names, return shapes, the JSON encoder, `os.replace` and which helper not to call. | Observable rows only; the rest goes to the design notes. |
| D11-4 | `schema_version` is written as 1 and never checked on read (`variant_execution_service.py:478-486`). | Keep. A version check is deferred until a version 2 exists (rule: defer). R-VAR-002.7 states it. |
| D11-5 | `gathered` is written (`manifest_writer.py:358-362`) but nothing reads it; the save plan names it as future work (`app.py:1453-1455`, LED .63). | Keep the write rows (R-MAN-SER-001.9, .10); R-VAR-002.19 records that nothing reads it. If the batch that adds plan rows for the gather does not read it, delete the key. **Superseded by D11-58** (batch-100 reads and carries `gathered`). |
| D11-6 | A verify mismatch is reported but the save stays (`app.py:9314-9322`). | Keep (R-MAN-VERIFY-001.7). |
| D11-7 | Name refusals go to the status line only; file problems also raise an error notice (`app.py:8869`, `8916`, `8927`, `9215`, `9251`). | Keep (R-TUI-012.19, R-PROJ-ROLLBACK.13). **Superseded by D11-56**: a refusal is painted in the Save dialog; the status line and the notice are for a save the dialog did not prepare. |
| D11-8 | A variant or MAC added by a later load does not update project.json; only Save project writes it. The variant list always comes from the folder. | Keep (R-PROJ-002.10). **Superseded by D11-59.** |
| D11-9 | S0's table holds project behaviour: the gather (HLR-138, LLR-138.1–138.4), the Load project dialog (HLR-151, LLR-151.1), the Save-project sentence of HLR-155 (LLR-155.4), the project list (HLR-162, LLR-162.2). | Moved into S11 (R-PROJ-GATHER.x, R-TUI-013.x, R-TUI-012.14), pointers left in S0 (rule D-9). |
| D11-10 | Execute scope reads each variant from its file, so applied but unsaved changes of the session are not part of the run (`variant_execution_service.py:757-764`). | Keep: the run works on saved files; R-VAR-002.25 states it. |
| D11-50 | Batch-100 states much of HLR-164 … HLR-178 as mechanism: function names, AST censuses, the 150 ms recompute of the plan, the digests computed once per dialog open, the first frame before the image decision, `SaveProjectScreen.plan`, `_session_snapshot`, `predict_placement` (LLR-163.7), the `save_patched` split, private staging, worker steps, the one-function preparation (LLR-175.6). LLR-163.5 and LLR-163.7 state product behaviour only through their texts. | Not requirement text (D11-1, D11-3). The rows state the observable behaviour: LLR-163.5 is R-PROJ-002.2, LLR-163.7 is R-PROJ-ROLLBACK.8 and the action words of CTX-SAVE. The tests that verify mechanism only are listed in D11-51. |
| D11-51 | Tests that verify implementation only (batch-100, S11 HLRs). | TC-B100-69 except its save-back staging node: `test_tc_b100_69_rederive_writes_nothing_into_the_session_map`, `test_tc_b100_69_save_patched_writes_the_pre_split_bytes`. Mechanism nodes of ids whose other nodes verify rows: `test_tc_b100_07_ast_census_every_post_creation_return_removes`, `test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf`, `test_tc_b100_08_call_site_census`, `test_tc_b100_08_the_one_reset_call_sits_in_the_install_handler`, `test_tc_b100_09_domain_matches_the_live_source_census`, `test_tc_b100_09_two_cold_loads_have_equal_snapshots`, `test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag`, `test_tc_b100_10_change_service_is_rebound`, `test_tc_b100_10_outgoing_service_finishes_after_rebind`, `test_tc_b100_14_deciding_writes_nothing`, `test_tc_b100_27_no_shared_staging_name_in_the_writer_source`, `test_tc_b100_47_one_preparation_ast_census`, `test_tc_b100_49_constructor_is_keyword_only_and_computes_nothing`, `test_tc_b100_59_gather_service_imports_no_change_module`, `test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload`, `test_tc_b100_65_plan_is_read_only`, `test_tc_b100_65_recompute_is_a_150ms_debounce`, `test_tc_b100_65_first_preview_after_the_first_frame_and_once_while_idle`, `test_tc_b100_65_session_decided_once_per_open_case06`, `test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes`, `test_tc_b100_65_emitting_4mib_image_recomputes_fast`, `test_tc_b100_65_first_frame_before_the_image_decision`, `test_tc_b100_65_the_preview_and_the_dialog_list_nothing_themselves`, `test_tc_b100_65_payload_plan_field_and_preview_value_types`, `test_tc_b100_68_prediction_walks_the_same_names_as_the_placement`, `test_tc_b100_53_save_refuses_before_any_worker_then_writes_on_one`, `test_tc_b100_53_a_project_reload_reuses_the_a2l_parse`. |
| D11-52 | The canon restatement of R-TUI-012 (ledger LED .13) says Save project emits "when the image differs from its source or the document holds entries". LED .14 (round 3) withdrew that trigger: with it a check document refused every save and unchanged data were written as new variants. The code emits only when the re-derived data differ from the source's data (`app.py:12402-12428`). | Rows follow LED .14 and the code (R-PROJ-IMAGE.1 … .3). The batch's canon fold of R-TUI-012 must take the LED .14 condition, not the LED .13 text. |
| D11-53 | LLR-015.3, project half (LED .13; S8 D8-35): Save project emits 32 data bytes per S19 record with the source's S0 and offers no width choice. | R-PROJ-IMAGE.7 and .8 state the width and the S0; R-PROJ-IMAGE.11 states that no choice is offered. |
| D11-54 | HLR-178 asks for every problem "with no truncation". The code lists at most 102 problem rows and counts the rest in one `more problems` row, a bound from security review SEC6-5 (`variant_execution_service.py:118-121`, `2301-2320`). | The requirement follows the code (CTX-LOADRES problem bound, R-LOADRES-7); the batch's canon fold must state the bound. |
| D11-55 | R-TUI-013 (canon) points to the Load project dialog; batch-100 Inc 9b replaced it with the one Load dialog (S7), which `p` opens on its projects list. | R-TUI-013.1, .3, .4 and .5 are retired in favour of S7 R-LOADDLG.1, .24, .54 / .60 and .70. S11 keeps what a project load does (R-TUI-013.2 and .6 … .20). |
| D11-56 | Save refusals: batch-100 HLR-175b paints the refusal in the Save dialog before Save and keeps the dialog open; the status line and the error notice remain only for a save the dialog did not prepare (`app.py:10706-10716`, `11384-11440`). The review had every refusal as a status line (R-TUI-012.7 … .19, D11-7). | Batch-100 wins: each save check gives a refusal text (CTX-SAVE); R-SAVEDLG-9 paints it, R-TUI-012.33 and .19 give the status and the notice for a save the dialog did not prepare. D11-7 is superseded. |
| D11-57 | Manifest read cap: the review had 256 MiB (the copy limit); batch-100 LLR-169.4 reads at most 1 MiB and caps every array at 1 000 entries (`variant_execution_service.py:98-104`, `1022-1076`). | Batch-100 wins: CTX-MANIFEST read cap and entry cap; R-VAR-002.2; R-MANIFEST-READ.3. |
| D11-58 | `gathered`: the review recorded that nothing reads it and would delete the key if no reader came (D11-5). Batch-100 LLR-168.1 reads it, and every writer carries it (`app.py:14340-14365`). | D11-5 is superseded: R-VAR-002.19 now reads `gathered`; R-MANIFEST-READ.1, .2, R-MANIFEST-WRITE.1. |
| D11-59 | A later load into the open project: the review kept project.json unchanged (D11-8). Batch-100 LLR-168.3 rewrites project.json after every file placed in the open project, carrying the records it does not own (`app.py:14406-14476`). | D11-8 is superseded: R-PROJ-002.10 is restated; R-PROJ-WRITER.1 … .4, R-PROJ-SAVEBACK.1 … .3. |
| D11-60 | A save with nothing selected: the review's R-PROJ-ASSIGN-001.5 wrote an empty composition. Batch-100 LLR-171.6 and .6a keep the carried `batch` and `assignments` (`app.py:11826-11835`). | Batch-100 wins: R-PROJ-ASSIGN-001.5, .6. D11-24 keeps only the pre-selection. |
| D11-61 | Manifest findings on project load: the review asked for each as a finding line (D11-26). Batch-100 HLR-169 lists them as `manifest damaged` problems in user terms and sends the codes to the log only. | D11-26 is superseded: R-TUI-013.14, R-PROJCHK-3, R-PROJCHK-17. |
| D11-62 | The gather's common-library branch: the review would delete it (D11-13). Batch-100 LLR-171.6b uses it to bring back a recorded composition document the project no longer holds (`app.py:11836-11859`). | D11-13 is superseded: keep the branch (R-PROJ-ASSIGN-001.7). |
| D11-73 | The MAC and A2L refusals of a save: the review had `Project already has a MAC file.` / `... an A2L file.` (R-PROJ-001.11, .12). Batch-100 LLR-167.6c, .6d and .6f refuse in the save plan, name the target and its file, and exempt the session's own A2L. | Batch-100 wins: R-PROJ-001.11, .12 restated as checks C-18, C-19. |
| D11-63 | `_session_snapshot`: the review would move it to test support (D11-14). Batch-100 LLR-165.2 requires the app to expose it for the leak check. | D11-14 is superseded: keep it in the app; it is a test seam, not product behaviour (no row). |
| D11-64 | The save plan's `target_kind` and `manifest_keys`: the review would defer or delete them (D11-16). Batch-100 Inc 11 paints the plan: the kind gives the target line, the key list is the plan's record of the keys the save writes (`test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from`). | D11-16 is superseded: keep both. |
| D11-65 | The Save dialog prototype round of batch-100 Inc 11 (rulings G-A / G-B, P-1 … P-6) with the operator's verdict settled D11-40: no parent box, the open project's name pre-filled and selected, an empty name explained in the dialog; ruling Q4 keeps the assignment lists of the open project as they were. | D11-40 is superseded; the dialog is written as requirements now (R-SAVEDLG-1 … .28, R-TUI-012.3), not prototype first. |
| D11-66 | The closed-document notice (`Closed the Patch Editor document (<n> entries); unsaved changes were not kept`) was removed at batch-100 Inc 10: the load question (HLR-174) asks before unsaved work is lost (`test_tc_b100_10_interim_discard_notice`). | R-PROJ-RESET.2 is retired; D11-37 is obsolete. |
| D11-67 | `Manifest active_variant '<id>' not found - activating the first variant.` was removed (LLR-169.6); the Load-result panel lists the recorded variant as `missing`. | R-VAR-001.4 is retired; R-PROJCHK-13 states the problem. |
| D11-69 | The A2L unload of a session with no data file (LLR-171.2h) and the parsed A2L dropped on unload (LLR-165.4) are unload behaviour. | They live with S5's unload rows (rule D-9); passed to S5. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D11-13 | The gather resolves a composition name against the common `workarea/patches/` library (`project_gather_service.py:480-494`). The Save dialog offers only project documents, so this branch is never reached from the product; when reached from a direct call, the manifest entry names a file the project does not hold. | Delete the common-library branch. **Superseded by D11-62.** |
| D11-14 | `_session_snapshot` (`app.py:9885-10019`) is used only by `tests/test_b100_session_reset.py`. | Move it into the test support code. **Superseded by D11-63.** |
| D11-15 | `Execute: unknown scope` (`app.py:4585-4587`): the Scope button cycles three fixed values, so it never fires; the service still raises on a bad value. | Delete the app-side check. |
| D11-16 | The save plan's `manifest_keys` and `target_kind` (`project_gather_service.py:774-777`) are read only by tests; the plan is meant to be painted in the Save dialog later (R-PC). | Defer to the batch that paints the plan; delete them if that batch does not land. **Superseded by D11-64.** |
| D11-68 | The `has no project.json` refusal of a project load (`app.py:13428-13432`; LLR-171.2e, retired by LLR-173.4a) is reached only when the folder changes between the project list and the check, since a folder with neither project.json nor a project file is not listed. | Keep it as a guard (it is used); no row. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D11-20 | Saving the open project again is refused with `Project already has an A2L file.` whenever the project holds an A2L, even the session's own (`app.py:9011-9022`; a project load sets the session's A2L to the project's file, `app.py:12473`, `12755-12757`). The MAC guard checks the name (`app.py:8997-9010`). | Refuse only another A2L file (R-PROJ-001.12). Not run; add a test that saves a loaded S19 + A2L project into itself. **Settled by batch-100 Inc 8b** (3a4a309): the save plan exempts the session's own A2L, by path or by name and bytes (`app.py:12718-12753`); R-PROJ-001.12 reads Yes. |
| D11-21 | Save project writes an A2L-only project (`app.py:8707`), but Load project refuses it with `No supported files in project: <name>` (`app.py:10035-10038`). | Load it (the A2L alone), as S5 makes every slot independent (D5-18) (R-TUI-013.8). **Settled by batch-100 Inc 8b** (3a4a309): an A2L-only project loads (R-PROJ-A2LONLY.1); R-TUI-013.8 now names a folder with neither a data file nor an A2L file. |
| D11-22 | Load project lists every non-reserved folder of the work area (`app.py:10117-10123`), empty folders and links included; the save's own test of "is a project" is stricter (`app.py:8811-8826`). | List only projects of CTX-PROJECT (R-TUI-013.2). `test_list_projects_skips_files_and_sorts_names` changes. **Settled by batch-100 Inc 8b and 9b** (3a4a309, 12d0f81): the project list leaves out links, folders outside the work area, names ending in a dot or a space, and folders that hold no project (`app.py:13869-13920`). |
| D11-23 | The Save dialog offers only `.json` files at the top of the project folder (`app.py:6943-6951`); the Patch Editor and the gather put documents in `patches/` and `checks/` (`project_gather_service.py:83-85`), so nothing is offered in normal use. | Offer the project documents of CTX-PROJECT, as entries (`patches/<name>.json`) (R-PROJ-ASSIGN-UI-001.3). Re-verified open at 570b4b5 (`app.py:8064-8098`). |
| D11-24 | A re-save starts with nothing selected (`screens.py:572-591`) and writes the payload as is (`app.py:9185-9192`), so the earlier `batch` and `assignments` are erased. | Pre-select the manifest's composition (R-PROJ-ASSIGN-UI-001.5). **Partly settled by batch-100 Inc 8b** (LLR-171.6, .6a): a save with nothing selected keeps the recorded composition (R-PROJ-ASSIGN-001.5, .6). The lists still start with nothing selected (`screens.py:1037-1066`), so a re-save that selects one document replaces the rest. |
| D11-25 | Every save writes project.json. Execute scope then counts the manifest as present (`app.py:4595`) and runs `batch` + `assignments` only (`variant_execution_service.py:680-689`): with an empty composition, the Patch Editor's document is ignored and each variant runs nothing, `ok`. | A manifest that names no file counts as no manifest (CTX-EXEC; R-VAR-002.21, .24). Re-verified open at 570b4b5: any manifest still counts as present (`app.py:5664`); the `active_document` that batch-100 Inc 8a records is not used by Execute scope. |
| D11-26 | Manifest findings on project load are dropped (`app.py:10051-10071`); only an unknown `active_variant` is reported. | Show each finding line (R-TUI-013.14). **Superseded by D11-61.** |
| D11-27 | Gather findings are written to the log only (`app.py:9156-9157`). | Show them as finding lines (R-PROJ-GATHER.6 … .8). Re-verified open at 570b4b5 (`app.py:11860-11861`). |
| D11-28 | Variant activation goes through the general load (`app.py:7065`), which copies the project's file into `temp/` (`app.py:10378-10384`), against S5 R-TUI-002.2. A project load parses on the main thread (`app.py:10097-10099`, `load_selected_file`), against S5 R-TUI-012L.5. | One project load path: read the project's files in place, parse on the worker (R-VAR-001.9, .12). **Partly settled by batch-100 Inc 12b** (1571f4c): a project load reads its files in place and parses them on a worker (`app.py:13507-13647`; `test_tc_b100_53_case06_project_load_keeps_the_loop_free_and_reports_parse_bytes`); a Workarea Files pick parses in place on the file-load worker (`test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker`). Variant activation still goes through `load_from_path`, which copies into `temp/` (`app.py:8794-8800`, `15124`). |
| D11-29 | Only worker loads copy into the open project (`app.py:13105-13106`); an S19, Intel HEX or MAC file picked in the Workarea Files list (`app.py:10663`) is loaded but not added. | The same rule for every load path (R-PROJ-002.1). Re-verified open at 570b4b5: the work-area pick loads with `sync_project=False` (`app.py:15619-15621`; `test_tc_b100_53_workarea_pick_begins_a_file_load_and_never_syncs_the_project`), while the Load dialog's preview of that row says `becomes the active variant of project <P>` (`app.py:8641-8646`, S7 LLR-173.6c). The preview promises what the load does not do; the fix makes both true. |
| D11-30 | A MAC loaded while the open project holds another MAC is loaded into the session but not into the project, with no message (`app.py:10244`, `10250-10260`); the next save is refused. The A2L in the same case is refused at load (S2 R-A2L-004.5). | Refuse the MAC load the same way (R-PROJ-002.6). Re-verified open at 570b4b5 (`app.py:14700-14713`). |
| D11-31 | The save folder is `<parent>/<clean name>` with the dialog's parent folder (`app.py:8711-8715`, `8882`). A parent outside the work area is refused only after the folder is created and removed again; a parent inside the work area but deeper (for example `temp/`) gives a project Load project never lists. | The project folder is always the save target in the work area (R-TUI-012.4); the refusal `Parent folder not found or not a directory.` goes with the parent folder. The dialog change itself is prototype first (D11-40). **Settled by batch-100 Inc 8b and Inc 11** (3a4a309, 53d08d5): the dialog has no parent box and its payload names the work area (R-SAVEDLG-6, R-TUI-012.4); a parent other than the work area is refused before any folder exists (R-TUI-012.34). |
| D11-32 | Execute scope does not save patched Intel HEX variants: `HEX save-back not supported this batch - patched image not persisted` (`variant_execution_service.py:811-815`), although `save_patched_image` writes HEX (`changes/apply.py:727-731`). The text also names a batch. | Save `<variant id>-patched.hex` (R-VAR-002.32). Re-verified open at 570b4b5 (`variant_execution_service.py:2595-2599`). |
| D11-33 | The batch save-back passes no S0 header (`variant_execution_service.py:797-804`), so a patched S19 variant loses its header. | Pass the variant's S0 header (R-VAR-002.33). Re-verified open at 570b4b5 (`variant_execution_service.py:2581-2588`). |
| D11-34 | The per-variant result line is printed when the variant ends (`variant_execution_service.py:895-900`) and again in the final report (`app.py:4735-4741`); the status area shows 4 lines. | Print it once (R-VAR-002.36). Re-verified open at 570b4b5. |
| D11-35 | The verify compares `active_variant`, `batch` and `assignments` only (`manifest_writer.py:717-723`); `declared_regions` is written but not checked. | Compare every key written (R-MAN-VERIFY-001.3). Re-verified at 570b4b5: batch-100 added `files`, `derived_from` and `active_document` to the compared keys, not `declared_regions` or `gathered` (`manifest_writer.py:895-910`); the recommendation now covers `gathered` too (R-MAN-VERIFY-001.3). |
| D11-36 | The manifest is staged at the fixed name `temp/project.json` and that name is deleted afterwards (`manifest_writer.py:507-528`), unlike the private staging every other placement uses (S0 HLR-155). Its own containment check resolves the path before it looks for links (`manifest_writer.py:400-411`), so it never sees one; the shared guard reads the unresolved path (`workspace.py:631-750`). | Private staging and the shared destination guard with this app's work-area root (R-MAN-WRITE-001.4, .5). **Settled by batch-100 Inc 7** (052dc3a): private staging (`manifest_writer.py:640-650`) and the shared guard on the unresolved path with the app's root (`manifest_writer.py:490-523`). |
| D11-37 | The closed-document notice says `(1 entries)` (`app.py:10109-10112`). | `(1 entry)` (R-PROJ-RESET.2). **Obsolete** (D11-66): the notice was removed at Inc 10. |
| D11-38 | The Load project dialog (`screens.py:707`) and the Select variant dialog (`screens.py:976-983`) build `Label`s from folder and file names, which read markup; a file named `[red]x.s19` is styled. The Save dialog lists (`screens.py:572-591`) use the same names; not checked. | Plain text (R-PROJ-ASSIGN-UI-001.6); add the three dialogs to S1's safe-text views. **Partly settled by batch-100 Inc 9b and Inc 11** (12d0f81, 53d08d5): the Load dialog (S7) replaces the Load project dialog and paints names literally; the Save dialog paints names literally (R-PROJ-ASSIGN-UI-001.6). The Select variant dialog still reads markup (`screens.py:1590-1606`; S7 R-DLG.13). |
| D11-39 | Execute scope with more than one MAC or A2L file in the project runs with neither (`variant_execution_service.py:959-962`), without a message. A later S19, HEX or MAC load into such a project is skipped with a log line only (`app.py:10165-10168`). | Refuse the run with the rule's status (R-VAR-002.22); show the rule's status on the skipped load (R-TUI-014.1, .2). Re-verified open at 570b4b5. |
| D11-42 | Save project writes a patched S19 image with the source's S0 (`app.py:9053`) but no terminator address (`app.py:9046-9056`), and the batch save-back passes neither (`variant_execution_service.py:797-804`); the writer then puts address 0 in every terminator (`changes/io.py:1823`), so the source's start address is lost. S8 D8-29 asked S11 to decide. The other whole-image writers keep the source's: save-back (S8 R-S19-EMIT.11), the CRC write (S13 D13-28), WRITE-OUT (S15 D15-14). | Same rule here: keep the source's terminator address and S0 data (R-PROJ-IMAGE.8, .9; R-VAR-002.43; the batch S0 is D11-33). Re-verified open at 570b4b5: `render_patched_image` gets no terminator address (`app.py:12431-12437`). |
| D11-70 | Execute scope writes `<variant id>-patched.s19` into the project (`variant_execution_service.py:2581-2588`) but does not rewrite project.json, unlike the five writers of LLR-168.3; the next project load lists the file as `not recorded`. | Rewrite project.json after a run that saved a variant, with the carried records (R-PROJ-EXEC.1). |
| D11-71 | After a file is placed in the open project, the project.json rewrite paints `Project saved + manifest verified` (`app.py:12976-12979`), although no project was saved. | Paint `project.json updated + verified` for a rewrite outside Save project (R-MANIFEST-VERIFY.1). |
| D11-72 | A load into the open project whose folder was deleted outside the app re-creates the folder empty (`project_dir.mkdir(parents=True, exist_ok=True)`, `app.py:14614-14630`, `14737-14753`), places the file there and writes a fresh project.json (fix round 2, observation R-1/SE5-12b-2, not fixed). | Refuse with the `... sync NOT done ... could not be read` status of R-PROJ-002.12 / .13 and create no folder. |

**Prototype first** (visual; prototype round with real captures and the operator's verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D11-40 | The Save dialog asks for a parent folder that must be the work area (D11-31); a re-save needs the open project's name typed again; an empty name box gives no message; the assignment lists show the open project's variants even when a new project name is typed. | The dialog without the parent box: is the open project's name pre-filled, how a blank name is explained, how the lists show that they belong to the open project. **Superseded by D11-65.** |
| D11-41 | Regions typed in hex (`cal,0x1000,0x10FF`) come back after a project load in decimal (`cal,4096,4351`) (`screens.py:1683-1688`). | Hex or decimal in the pre-filled region lines. |

**Passed to other groups**

- **S0**: leave pointers for HLR-138 / LLR-138.1–138.4, HLR-151 / LLR-151.1, the Save-project sentence of HLR-155 / LLR-155.4, HLR-162 / LLR-162.2; their rows now live in S11 (D11-9).
- **S1**: add the Load project dialog, the Select variant dialog and the Save dialog's lists to the safe-text views (D11-38).
- **S2**: R-A2L-004.5 (A2L load refused when the open project has an A2L) stays S2's; S11 cites it (R-PROJ-002.7) and gives the MAC the same rule (D11-30).
- **S5**: R-TUI-002.2 ("read it where it is") is not met for a variant activation, and R-TUI-012L.5 ("screen responsive") is not met for a project load or a Workarea Files pick (both parse on the main thread through `load_selected_file`); their "Code today" should read Partly, fix in D11-28. The PROJ row of CTX-WORKSPACE uses S11's variant id.
- **S6**: R-TUI-016 (project name in the status bar) cites CTX-PROJECT; the keys `s`, Ctrl+S, `p`, `v` are in its key-bar rows.
- **S7**: the Save, Load project and Select variant dialogs' widgets and layout (D11-40).
- **S8**: Save project re-applies the change document and verifies the patched image with S8's rules (R-PROJ-IMAGE.x); the batch save-back's S0 header (D11-33).
- **S10**: the "Execute over variants" controls (Scope button, Execute scope) that start S11.13.
- **S12**: the Reports dialog's region box and Generate (R-RPT-REGION-PERSIST-001.1, 002.3); reports built from the last execution.
- **S13**: the CRC Designer's "last loaded template" that the gather copies (R-PROJ-GATHER.2).
- **S5** (batch-100): LLR-165.4, the unload drops the parsed A2L (`test_tc_b100_11_unload_all_clears_the_parsed_a2l`, `test_tc_b100_11_unload_a2l_alone_clears_the_parsed_a2l`, `test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags`), and LLR-171.2h, the A2L unload of a session with no data file detaches the A2L (`test_tc_b100_32_unload_of_an_a2l_only_session_clears_the_a2l`), are unload behaviour: S5's unload rows cite these nodes (D11-69). R-TUI-012L.5: a project load now parses on a worker (D11-28).
- **S6** (batch-100): S11 cites S6 R-BUSY-REFUSE.1 (Save project and Load refused while a session action runs) and S6 R-QUIT (no Load-result panel after a confirmed quit; no partial save); the focus after the Load-result panel closes is S6's (LLR-166.1).
- **S7** (batch-100): R-TUI-013.1, .3, .4, .5 are retired in favour of R-LOADDLG.1, .24, .54 / .60, .70. The project-load refusals R-TUI-013.15 … .18 (link, outside, could not be read, not a project) stay in S11; S7 R-LOADDLG.66 and .67 should cite R-TUI-013.18 and .17. The open project's preview shows the last load result (LLR-178.3, CTX-LOADRES). The work-area row preview `becomes the active variant of project <P>` (LLR-173.6c) is false until D11-29 is fixed.
- **S8** (batch-100): the save-back into the open project is R-PROJ-SAVEBACK.1 (active variant), .2 (derived_from), .3 (no project open) and R-PROJ-002.10 (the project.json rewrite); R-CHG-003.8 and D8-37 cite them. The Save project half of LLR-015.3 is R-PROJ-IMAGE.7, .8, .11 (S8 D8-35).
- **S10** (batch-100): Save project clears the Patch Editor's unsaved mark only when it wrote the editor's document (R-PROJ-DOC.15, .16), and paints R-PROJ-DOC.17 when it records a file whose edits are only in memory; S10 R-PE-039.x cite them.
- **S12** (batch-100): R-RPT-REGION-PERSIST-001.1 cites S12 R-RPT-002.28 for its exception.
- **S13** (batch-100): the used template's `copied but not recorded` line is R-PROJ-GATHER.10.
- **S16** (batch-100): after a save as the Flow panels use the new folder: R-SAVEAS-8.
- **S1** (batch-100): the Load-result panel, the file status, the load summary line and the Save dialog show names as painted names (CTX-PROJECT, S7 CTX-LOADDLG); list them in the safe-text views with that rule.
- **S3** (batch-100): the Load-result panel's OK and warning colours (R-LOADRES-14 … .16) use the palette roles.
- **S0** (batch-100): rows for HLR-164, 165, 167 … 171b, 175 … 175f, 178 (absorbed here); the HLR-151 / LLR-151.1 pointer moves to S7 (D11-55).

---

**Received from later groups** (after all groups were written)

- S11.1 (S5: projects, variants, project save, `validate_project_files`) → covered by S11.1 … S11.8 (R-TUI-012.x, R-TUI-014.1 … .6, R-PROJ-002.x).
- S11.2 (S7: Save project, Load project and Select variant contents) → covered by CTX-SAVE, S11.2, S11.6, S11.7, R-PROJ-ASSIGN-UI-001.x.
- S11.3 (S8: Save project writes through S8.7 and S8.8; terminator address, D8-29) → rows R-PROJ-IMAGE.7 … .10, R-VAR-002.43; D11-42.
- S11.4 (S9: variant execution runs the S9 engine) → covered by R-VAR-002.28.
- S11.5 (S10: running a scope and its status lines) → covered by S11.13 (R-VAR-002.20 … .41).
- S11.6 (S12: reports read the kept execution; the region box) → row R-VAR-002.42 (the run keeps its results); the region box is covered by R-RPT-REGION-PERSIST-001.1; D12-24 is S12's.
- S11.7 (S13: the used template; `<project>/templates/`) → covered by CTX-SAVE "used template" (S13 R-CRC-TEMPLATE-001.12), CTX-PROJECT "project homes", R-PROJ-GATHER.2.
- S11.8 (S15: flow outputs become variants; project refs; reserved homes) → covered by CTX-PROJECT ("project file", "variant", "reserved home" lists flows, flowsets, reports) and CTX-MANIFEST ("entry", "unsafe entry"); S15 D15-4.
- S11.9 (S17: `<project>/splits/`) → covered by CTX-PROJECT ("reserved home" and "project homes" list splits); creating it is S17 R-SEG-PLACE.1, .2.

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added (187): R-PROJ-CONTAIN.1, R-TUI-012.22 … R-TUI-012.36, R-SAVEDLG-1 … R-SAVEDLG-28, R-PROJ-IMAGE.11 … R-PROJ-IMAGE.14, R-PROJ-MERGE.1 … R-PROJ-MERGE.3, R-PROJ-GATHER.10, R-PROJ-GATHER.11, R-PROJ-DOC.1 … R-PROJ-DOC.22, R-PROJ-ROLLBACK.14 … R-PROJ-ROLLBACK.18, R-TUI-013.15 … R-TUI-013.20, R-PROJ-A2LONLY.1 … R-PROJ-A2LONLY.5, R-PROJ-OPEN.1, R-PROJ-OPEN.2, R-PROJ-002.11 … R-PROJ-002.13, R-PROJ-WRITER.1 … R-PROJ-WRITER.4, R-PROJ-SAVEBACK.1 … R-PROJ-SAVEBACK.3, R-MANIFEST-READ.1 … R-MANIFEST-READ.17, R-MANIFEST-WRITE.1 … R-MANIFEST-WRITE.8, R-MANIFEST-VERIFY.1, R-MANIFEST-KEEP.1 … R-MANIFEST-KEEP.5, R-PROJ-ASSIGN-001.6, R-PROJ-ASSIGN-001.7, R-PROJ-EXEC.1, R-SAVEAS-1 … R-SAVEAS-14, R-PROJCHK-1 … R-PROJCHK-18, R-LOADRES-1 … R-LOADRES-18.
- Rows changed (73): R-TUI-014.1, R-TUI-014.4, R-TUI-012.1 … R-TUI-012.21, R-PROJ-001.4, R-PROJ-001.11, R-PROJ-001.12, R-PROJ-001.7, R-PROJ-IMAGE.1 … R-PROJ-IMAGE.3, R-PROJ-IMAGE.7 … R-PROJ-IMAGE.9, R-PROJ-001.8, R-PROJ-GATHER.1, R-PROJ-GATHER.6, R-PROJ-ROLLBACK.1, R-PROJ-ROLLBACK.2, R-PROJ-ROLLBACK.6, R-PROJ-ROLLBACK.8, R-TUI-013.2, R-TUI-013.6, R-TUI-013.8, R-TUI-013.9, R-TUI-013.11 … R-TUI-013.14, R-PROJ-RESET.1, R-PROJ-RESET.3, R-VAR-001.1, R-VAR-001.3, R-VAR-001.9, R-PROJ-002.1, R-PROJ-002.4, R-PROJ-002.6, R-PROJ-002.8, R-PROJ-002.10, R-VAR-002.2, R-VAR-002.14, R-VAR-002.19, R-MAN-SER-001.1, R-MAN-SER-001.7, R-MAN-WRITE-001.4 … R-MAN-WRITE-001.6, R-MAN-VERIFY-001.2, R-MAN-VERIFY-001.3, R-PROJ-ASSIGN-UI-001.3, R-PROJ-ASSIGN-UI-001.5, R-PROJ-ASSIGN-UI-001.6, R-PROJ-ASSIGN-001.5, R-RPT-REGION-PERSIST-001.1.
- Rows retired (6): R-TUI-013.1, R-TUI-013.3, R-TUI-013.4, R-TUI-013.5, R-PROJ-RESET.2, R-VAR-001.4 (D11-55, D11-66, D11-67).
- Context notes: CTX-PROJECT, CTX-SAVE and CTX-MANIFEST changed (project, save checks C-13 … C-24, save plan, summary rows, read cap, entry cap, new keys); CTX-LOADRES new.
- Decisions added: D11-50 … D11-67, D11-69, D11-73 (follow the code or move), D11-68 (remove), D11-70 … D11-72 (code change).
- Decisions superseded: D11-5 (by D11-58), D11-7 (D11-56), D11-8 (D11-59), D11-13 (D11-62), D11-14 (D11-63), D11-16 (D11-64), D11-26 (D11-61), D11-40 (D11-65); obsolete: D11-37 (D11-66).
- Decisions settled by batch-100: D11-20, D11-21, D11-22, D11-31, D11-36; partly: D11-24, D11-28, D11-38; re-verified open: D11-23, D11-25, D11-27, D11-29, D11-30, D11-32 … D11-35, D11-39, D11-42.
- Consolidation (items from S5, S7): cells changed R-TUI-013.2 (the trailing-dot nodes of TC-B100-37, -38, LLR-172.4e), R-TUI-013.17, .18 (S7 R-LOADDLG.67, .66 retired into them, S7 D7-34; their tests cited here), R-TUI-013.19 untested → tested and R-VAR-001.11 `<painted file name>`, tested (`test_tc_b100_45_refusal_lines_paint_names_literally`), R-RPT-REGION-PERSIST-002.1 (`test_tc_b100_46_project_load_adopts_declared_regions_after_the_reset`), R-PROJ-ROLLBACK.18 (`test_tc_b100_50_save_raise_ends_the_action_first`, passed uncited by S6). `Variant not found: <painted id>` (`app.py:8784`) is a guard for an id the Select variant dialog cannot return: no row. Already here: LLR-163.5, .7 (R-PROJ-002.2, R-PROJ-ROLLBACK.8), R-VAR-001.9 Partly, "device name" (CTX-SAVE), the sync refusals and their ruling (R-PROJ-002.12, .13, D11-72), the work-area pick that adds nothing (R-PROJ-002.1, D11-29). The open project's preview of the last load result (LLR-178.3) is S7 R-LOADDLG.83 (No, S7 D7-35).

## 6. Counts

| | Old S11 | Strict (093a7c0) | Reconciled (570b4b5) |
|---|---:|---:|---:|
| Requirement statements | 17 rows (+ 4 S0 HLR rows with their LLRs moved in) | 205 rows | 386 rows |
| Statements the code contradicts or that are not product behaviour | 7 (014 one S19; 013 temp only; 002 limits; VAR-001 worker; VAR-002 absent manifest; MAN-TUI `Where`; §17 design note) | 0 | 0 |
| Rows by form: U / When / While / If / Where | — | 15 / 77 / 0 / 113 / 0 | 29 / 122 / 6 / 229 / 0 |
| Rows that could not be written in EARS | — | 0 | 0 |
| Decisions | — | 37 (10 follow the code or move, 4 remove, 21 correct a defect, 2 prototype first; numbers not contiguous) | 61 (30 follow the code or move, 5 remove, 24 correct a defect, 2 prototype first; superseded and settled ones stay listed) |

Checked by script (`ears_lint.py`, `count_decisions.py`; 2026-11-01 at 570b4b5): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", final period, no repeated id across `review/`.
