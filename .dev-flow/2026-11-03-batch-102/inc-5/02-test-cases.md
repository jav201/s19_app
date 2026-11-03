# E1 test cases — Inc 5 — Patch Editor picker parity

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-PE-01 | Verify Patch Editor activation populates a performant picker. | normal | A2L with 10 000 measurable parameters is loaded; Patch screen selected. | Activate Patch Editor twice. | Picker mounts 200 rows; filter/status/page controls exist; second activation with same signature does not repopulate. | R-B102-PE-001/.005, full | Mount all rows or reset on activation. | not_run |
| TC-B102-PE-02 | Verify id isolation between mounted Check and Patch pickers. | normal | App composed with both rail panels mounted. | Census all `check_param_*` and `patch_param_*` ids. | Zero duplicate ids; all Patch picker widgets use the patch prefix. | R-B102-PE-002, full | Reuse a Check id in Patch. | not_run |
| TC-B102-PE-03 | Verify `Use parameter` populates entry inputs without document mutation. | normal | Image bytes `DE AD BE EF`; parameter `TorqueMax` at address `0x1000`, size 4; document entry count known. | Highlight row and activate use. | Address input is `0x00001000`; Bytes input is `DE AD BE EF`; document entries and dirty state are unchanged. | R-B102-PE-003, full | Add an entry directly or skip bytes. | not_run |
| TC-B102-PE-04 | Verify missing image bytes arm. | robustness | No image loaded; parameter address/size known. | Highlight row and activate use. | Address is populated; Bytes is empty; exact status line paints. | R-B102-PE-004, full | Fill Bytes with zeroes. | not_run |
| TC-B102-PE-05 | Verify preservation across screen entries. | normal | Filter/page/highlight are set in Patch A2L tab. | Leave to Workspace and return twice. | Filter, page and highlighted name remain identical. | R-B102-PE-005, full | Reset picker on screen activation. | not_run |
| TC-B102-PE-06 | Verify shared visual grammar and safe names. | robustness | Hostile A2L name is present. | Render Patch A2L tab. | Names are literal with zero markup spans; surfaces mirror Check filter/table/status/full-name/page controls. | R-B102-PE-006, full | Paint names via markup. | not_run |

## Notas de ejecución

- RED: TC-01..06 deben fallar en base por ausencia de pestaña/selector Patch.
- GREEN: validar contra la rama tras integrar Inc 5.
