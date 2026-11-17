# Batch-103 G3 — medición final timing/context

## Alcance y contexto

- Head: `795779add81875976ac3651f8862498426d45abf` (`795779ad`).
- Base: `0c3a6bd4674c3f2df90a7399898fc98429f5a200` (`0c3a6bd4`).
- Control para nodos ausentes en base: `6a8cfb0a9bb64b95dd9969fb08e05ae85c1bd6b4` (`6a8cfb0a`).
- Windows 11 10.0.26300; CPython 3.12.7; pytest 8.3.4; pytest-xdist 3.8.0; Textual 8.2.8.
- Un proceso pytest por lane/tree, ejecución serial, `-I -B -n0 -p no:cacheprovider`, stdin cerrado, bytecode y cache de pytest desactivados.
- `HOME`, XDG, `LOCALAPPDATA`, `TMPDIR`, `TEMP` y `TMP` aislados por lane. `CI`, variables de clipboard/runner, `NO_COLOR` y `CLICOLOR*` sin definir; `TERM=xterm-256color`, `COLORTERM=truecolor`.
- No se usó clipboard real ni `getloadavg` como medición del entorno. El único `getloadavg` registrado está en el traceback propio de B95/1.
- Los cuatro nodos nuevos no existen en base; por eso su contraste es head/control. Los nueve nodos antiguos se ejecutaron en base/head.
- JUnit, logs y esta comparación están fuera de los árboles, en este directorio `artifacts/`.

## Totales

| Lane | Seleccionados | PASS | FAIL | Salida pytest | Wall externo |
|---|---:|---:|---:|---:|---:|
| head | 13 | 4 | 9 | 1 | 371.696 s |
| base | 9 | 0 | 9 | 1 | 80.637 s |
| control | 4 | 3 | 1 | 1 | 295.321 s |

Las duraciones por nodo siguientes son las de JUnit (incluyen setup/teardown); los cocientes `medida/límite` son valores `qc_tm`.

## Cuatro nodos nuevos

| Nodo | Base | Head | Control | Clasificación por nodo+firma |
|---|---|---|---|---|
| `test_b103_inc9_w_jobs.py::test_r_pe_bench_29_2_a_cursor_key_while_the_preview_result_arrives_is_handled_within_one_second` | ausente | PASS, 110.223 s; `0.928/1.000`, margen LOW 7.2% | PASS, 104.439 s; `0.672/1.000`, 32.8% | PASS en head/control; head queda con margen bajo. |
| `test_b103_inc9_w_jobs.py::test_r_pe_bench_82_1_a_key_is_handled_within_one_second_while_a_record_encode_runs` | ausente | PASS, 131.622 s; `0.738/1.000`, 26.2% | PASS, 131.559 s; `0.730/1.000`, 27.0% | PASS en head/control. |
| `test_b103_inc9b_at.py::test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds` | ausente | PASS, 42.983 s; mediana `0.141/0.200` (29.5%), máximo `0.329/0.500` (34.2%) | PASS, 46.725 s; mediana `0.140/0.200` (29.8%), máximo `0.391/0.500` (21.8%) | PASS en head/control. |
| `test_b103_inc9b_w.py::test_r_pe_bench_95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue` | ausente | FAIL, 9.486 s | FAIL, 9.091 s | Misma firma head/control: la condición `done - asked < GRACE_S` de `test_b103_inc9b_w.py:353` falla; al formatear su mensaje, `load()` en `:56` lanza `AttributeError: module 'os' has no attribute 'getloadavg'`. Sin fila `qc_tm`. |

## Nueve nodos antiguos

Control no aplica a estos nodos bajo la regla de ejecutarlo cuando el nodo es nuevo.

| Nodo | Base | Head | Clasificación por nodo+firma |
|---|---|---|---|
| `test_b100_focus.py::test_tc_b100_12_every_window_load_lands_on_its_target[map]` | FAIL, 17.817 s: timeout esperando el landing LLR-116.5; foco final `MemoryMapPanel#memory_map_panel` | PASS, 8.240 s | Cambio de firma/resultado base→head: el timeout de foco desaparece y el nodo pasa. |
| `test_b99_export.py::test_tc_b99_41_collision_reason_is_scrubbed_clipped_and_indexed` | FAIL, 0.006 s | FAIL, 0.006 s | Misma firma: el nombre sanitizado alcanza 261 caracteres frente al límite 260; la aserción esperada sobre `(segment ...)` no se alcanza. |
| `test_b99_export.py::test_tc_b99_41_part_way_failure_status_names_the_first_file` | FAIL, 15.790 s | FAIL, 16.362 s | Misma firma: falta `Already written: firmware_locality_00.s19` en el estado pintado; aparece truncado. |
| `test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[a2l-sync]` | FAIL, 5.602 s; `1.385/1.000`, -38.5% | FAIL, 6.099 s; `1.316/1.000`, -31.6% | Misma firma: `TC-B100-20 a2l-sync`, aserción `medida < timing_bound(1.0)`. |
| `test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[mac-sync]` | FAIL, 5.890 s; `1.468/1.000`, -46.8% | FAIL, 6.393 s; `1.502/1.000`, -50.2% | Misma firma: `TC-B100-20 mac-sync`, aserción `medida < timing_bound(1.0)`. |
| `test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[save-project]` | FAIL, 5.887 s; `1.330/1.000`, -33.0% | FAIL, 6.497 s; `1.660/1.000`, -66.0% | Misma firma: `TC-B100-20 save-project`, aserción `medida < timing_bound(1.0)`. |
| `test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[variant-append]` | FAIL, 5.821 s; `1.303/1.000`, -30.3% | FAIL, 6.409 s; `1.268/1.000`, -26.8% | Misma firma: `TC-B100-20 variant-append`, aserción `medida < timing_bound(1.0)`. |
| `test_b100_project_check.py::test_r_tst_111_112_arm_values_equal_the_product_stamps[scene]` | FAIL, 9.703 s; read `0.409/1.000`, load `1.214/1.000` | FAIL, 10.187 s; read `0.445/1.000`, load `1.434/1.000` | Misma firma: `sec6_5 load` supera el límite; el read pasa. |
| `test_b100_project_check.py::test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling` | FAIL, 9.816 s; read `0.455/1.000`, load `1.003/1.000` | FAIL, 10.743 s; read `0.670/1.000`, load `1.338/1.000` | Misma firma: `sec6_5 load` supera el límite; el read pasa. |

## Resumen de clasificación

- Nuevos: 3 PASS en head/control; B95/1 conserva la misma firma de fallo en head/control y no tiene base.
- Antiguos: `focus[map]` pasa en head frente al timeout de base; los otros 8 conservan la misma firma base/head.
- No se modificó código ni se corrigió ningún fallo.
