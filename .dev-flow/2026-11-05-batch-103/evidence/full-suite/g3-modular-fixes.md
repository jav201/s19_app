# Batch-103 G3 — corrección SLICE de modularización

## Alcance y decisión de integración

Este es el record batch-end de corrección para `trace_check.py --fixes`. No excluye rutas ni modifica el checker, producto, tests o requisitos históricos. Corrige la falta de cobertura documental de las 23 rutas que `g3-batch-trace.txt` declaró SLICE al comparar con base `0c3a6bd4674c3f2df90a7399898fc98429f5a200`.

Las 23 rutas pertenecen a contenido incorporado por la etapa 2 de la integración. La decisión y su materialización están en `../integration/RECORD.md` líneas 14 y 39-41: `b103-base2` `9ffe019dc9fbd83ca1ff56f958bcb4f01242677e` contenía la modularización `2dbd7d5a` y el PE split `a95d0ea9`; la etapa 2 produjo `aae4f445365ffcb75e1702f064ece38bff44c575`, cuyo árbol era byte-por-byte el de `b103-base2`.

## Origen modular común

Las primeras 22 filas son módulos generados por la modularización. Su origen demostrable es:

- requisitos y slice: `../../../2026-11-12-batch-modular/01-requirements.md` y `../../../2026-11-12-batch-modular/review/E5-slice-record.md`; la última ruta nombra individualmente cada archivo y sus IDs;
- mapa y grafo: `../../../2026-11-12-batch-modular/design/module-map.json` y `../../../2026-11-12-batch-modular/E2-module-graph.md` líneas 17-98;
- validación: `../../../2026-11-12-batch-modular/04-validation.md`, con verificación de identidad en `../../../2026-11-12-batch-modular/evidence/p2-reapply/verify.json` y el cierre E5 en `../../../2026-11-12-batch-modular/review/E5-close-packet.md`.

## Censo mecánico y mapping de las 23 rutas

La entrada es el conjunto de líneas `SLICE` de `g3-batch-trace.txt` líneas 1-23: 23 rutas únicas. Esta tabla tiene 23 filas, una por ruta, sin sustituciones por basename.

| # | Ruta exacta | IDs y record de origen |
|---:|---|---|
| 1 | `s19_app/tui/app/checks_diff.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:11` |
| 2 | `s19_app/tui/app/deps.py` | R-MOD.6.1, R-MOD.6.2; `E5-slice-record.md:14` |
| 3 | `s19_app/tui/app/file_load.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:15` |
| 4 | `s19_app/tui/app/flow.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:16` |
| 5 | `s19_app/tui/app/hex_view.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:17` |
| 6 | `s19_app/tui/app/issues_checks.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:18` |
| 7 | `s19_app/tui/app/loaded_state.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:19` |
| 8 | `s19_app/tui/app/mac_view.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:20` |
| 9 | `s19_app/tui/app/navigation.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:21` |
| 10 | `s19_app/tui/app/project_load.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:23` |
| 11 | `s19_app/tui/app/projects.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:24` |
| 12 | `s19_app/tui/app/reports.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:25` |
| 13 | `s19_app/tui/app/save_commit.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:26` |
| 14 | `s19_app/tui/app/save_plan.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:27` |
| 15 | `s19_app/tui/app/shared_io.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:29` |
| 16 | `s19_app/tui/app/workspace_view.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:31` |
| 17 | `s19_app/tui/screens_directionb/ab_diff.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:34` |
| 18 | `s19_app/tui/screens_directionb/check_editor.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:35` |
| 19 | `s19_app/tui/screens_directionb/deps.py` | R-MOD.6.1, R-MOD.6.2; `E5-slice-record.md:36` |
| 20 | `s19_app/tui/screens_directionb/loaded_artifacts.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:37` |
| 21 | `s19_app/tui/screens_directionb/map_parts.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:38` |
| 22 | `s19_app/tui/screens_directionb/memory_map.py` | R-MOD.2.6, R-MOD.4.1, R-MOD.6.1; `E5-slice-record.md:39` |
| 23 | `s19_app/tui/screens_directionb/patch_editor/checks.py` | P3a; commit `91d5ae562fab28c3adf902ead90dda30b905f07e`; origen inmediato `s19_app/tui/screens_directionb/patch_editor.py`, previamente mapeado a R-MOD.2.6, R-MOD.4.1 y R-MOD.6.1 en `E5-slice-record.md:40`; `../../../2026-11-12-batch-modular/steps.log:28`, `../../../2026-11-12-batch-modular/evidence/p3a-pe-split/compare.txt` y `rerun-alone.tsv` |

Para la fila 23 no se inventa un requisito nuevo: el commit `91d5ae56` documenta el movimiento verbatim de `ChecksMixin` desde `patch_editor.py`; `a95d0ea93340d26d8fe55025e9e7c21bef2d4f79` archiva la validación P3a. El censo posterior de Inc 7 confirma además la adición de la ruta exacta en `../../inc-7/evidence-remap/i7-remap-census-transcript.txt:20`.

## Cierre mecánico

Desglose del censo inicial: 16 módulos bajo `s19_app/tui/app/`, 6 módulos bajo `s19_app/tui/screens_directionb/` y 1 módulo bajo `s19_app/tui/screens_directionb/patch_editor/`; total 23. Las 23 rutas de entrada y las 23 rutas mapeadas son el mismo conjunto; no hay rutas sin origen demostrable ni entradas añadidas fuera del censo.

La primera repetición completa con este `--fixes` quedó archivada en `g3-batch-trace-with-fixes.txt`: redujo los 23 gaps iniciales a 3 rutas `__init__.py` ajenas al censo original. Esas tres rutas tienen origen explícito en `../../../2026-11-12-batch-modular/review/E5-slice-record.md:9,33` y `../../inc-7/evidence-remap/i7-remap-census-transcript.txt:20`, por lo que esos dos records existentes se añadieron como `--fixes` aplicables; no se cubrieron con texto vacío.

La repetición final con los 15 archivos `inc-*/01-requirements.md`, la base indicada, `--src s19_app`, `--canon REQUIREMENTS.md` y los tres records `--fixes` quedó archivada en `g3-batch-trace-final.txt`. Salida real: `trace_check: 14 US, 752 active requirements (10 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, CANON, 0 gap(s)`; exit status 0. No queda ningún cambio bajo `s19_app` sin mapping en esa pasada.
