<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026.08.23-rev43 | flow_hash: c4e93257d402cd87 | corpus: 62 requirement files | corpus digest: 05d91202a398d315 -->

# ATLAS-IFC — how is the application addressed?

2 FLOW declaration(s) · 1 COMPONENT declaration(s) · 519 declared requirement heading ids — one row per declaration.

### FLOW `loaded_artifacts_readout` — .dev-flow/2026-08-21-batch-85/01-requirements.md:277
- node `render_slots` — owner LLR-85.1
- node `_build_project_row` — owner LLR-85.3
- node `_slot_state` — owner LLR-85.2
- node `_build_slot_row` — owner LLR-85.2
- node `_build_unload_all_row` — owner LLR-85.1

### FLOW `ifc_pilot_authoring` — .dev-flow/2026-08-21-batch-85/01-requirements.md:306
- node `measure_address_consumers` — owner LLR-85.2
- node `correct_stale_consumer_notes` — owner LLR-85.5
- node `assert_census_form_membership` — owner LLR-85.6
- node `measure_per_surface_cost` — owner LLR-85.7

### COMPONENT `loaded_panel` — .dev-flow/2026-08-21-batch-85/01-requirements.md:334
- inputs : loaded: Optional[LoadedFile] ; project: str
- outputs : 
- parent : screen_workspace
- surface : LoadedArtifactsPanel

| output | address | cardinality | consumers | owner |
|---|---|---|---|---|
| `panel_handle` | `query_one("#loaded_panel")` | 1 | 5 declared | LLR-85.1 |
| `slots_container` | `query_one("#loaded_slots")` | 1 | 3 declared | LLR-85.1 |
| `slot_rows` | `query("#loaded_slots > Horizontal"), cells within a row INDEXED POSITIONALLY as kind then detail then optional unload` | 5 | 1 declared | LLR-85.1 |
| `artifact_slots` | `query(".loaded-detail"), INDEXED POSITIONALLY` | 3 | 4 declared | LLR-85.2 |
| `project_row` | `query(".loaded-project-detail")` | 1 | 2 declared | LLR-85.3 [+ABSORBED] |

## STATUS — the real rules, run at derivation

- [-] V10  01-requirements.md: 9 FLOW node(s), every one owned
- [-] V11  01-requirements.md: 5 OUTPUT(s), each with an address and a declared consumer list
- [!] V12  .dev-flow/2026-08-21-batch-85/01-requirements.md:334: COMPONENT loaded_panel: parent `screen_workspace` is not declared in this document, so balancing was NOT checked; this is not a pass
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:339: COMPONENT loaded_panel/panel_handle: reached by 2 undeclared file(s) — .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md, prototypes/legend_n8.INVENTORY.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:349: COMPONENT loaded_panel/slots_container: reached by 1 undeclared file(s) — s19_app/tui/screens_directionb.py. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:363: COMPONENT loaded_panel/artifact_slots: reached by 1 undeclared file(s) — .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md. Declare the ones that genuinely depend on this address; grep cannot tell a dependant from a mention
- [-] V14  01-requirements.md: 15 declared consumer(s), every one resolved
- [-] V19  01-requirements.md: 1 COMPONENT id(s), each declared exactly once
