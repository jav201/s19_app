# E1 test cases — Inc 7 — Flow file origins/chooser

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-FILE-01 | Verify card origin annotations. | normal | Blocks with refs resolving to project, temp, loaded, external and missing. | Render pipeline. | Five annotations paint exactly with the expected source labels. | R-B102-FILE-001, full | Omit origin annotation. | verified |
| TC-B102-FILE-02 | Verify Browse lists all sources. | normal | Active project has files, temp has files, artifacts are loaded. | Activate Browse on a ref field. | Chooser shows Project, Temp/workarea, Loaded and External path input. | R-B102-FILE-002, full | Show only manual input. | verified |
| TC-B102-FILE-03 | Verify picking candidates only fills the field. | normal | Add form and Edit modal each have a ref field; block count known. | Pick one candidate from each source. | Corresponding field updates; no block is added/replaced. | R-B102-FILE-003, full | Add/replace on pick. | verified |
| TC-B102-FILE-04 | Verify external import. | normal | Active project exists; external file `C:\tmp\calib.json`. | Submit external path. | File copies to workarea `external/`; field gets relative ref; original remains; existing destination gets suffix. | R-B102-FILE-004, full | Store absolute path or overwrite. | verified |
| TC-B102-FILE-05 | Verify no-project refusal. | robustness | No active project/workarea. | Submit external path. | Exact refusal; no copy; field unchanged. | R-B102-FILE-005, full | Copy outside workarea. | verified |
| TC-B102-FILE-06 | Verify unreadable external file. | robustness | External path points to missing/unreadable file. | Submit external path. | Exact `External file not readable: <name>`; field unchanged. | R-B102-FILE-006, full | Clear field. | verified |
| TC-B102-FILE-07 | Verify hostile names render literally. | robustness | Candidate filename contains markup/control bytes. | Open chooser and annotate cards. | Sentinel literal; zero markup spans/control bytes. | R-B102-FILE-007, full | Markup rendering. | verified |

## Notas de ejecución

- RED: TC-01..07 deben fallar en base por ausencia de anotaciones/Browse/importación externa.
- GREEN: validar tras Inc 7.
