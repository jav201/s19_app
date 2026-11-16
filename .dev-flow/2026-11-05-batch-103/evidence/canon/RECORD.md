# Batch 103 G3 — fold del canon

Base: `c1741dee6cf2488b7f28f228e6dd66aa2775893c`. Alcance: sólo los `01-requirements.md` bajo `.dev-flow/2026-11-05-batch-103/`; ningún packet histórico, producto o test fue editado.

## Inventario mecánico

`inventory.txt` enumera todas las definiciones activas, los estados retirados y los archivos de casos por incremento. Resumen (las filas activas incluyen citas y definiciones que otros incrementos reemplazan después):

| Incremento | Activas aquí | Retiradas aquí | Casos |
|---|---:|---:|---|
| 1a | 43 | 0 | `02-test-cases.md` |
| 1b | 24 | 2 | `02-test-cases.md` |
| 2 | 73 | 0 | `02-test-cases.md` |
| 3 | 86 | 0 | `02-test-cases.md` |
| 4 | 43 | 0 | `02-test-cases.md` |
| 5 | 28 | 0 | `02-test-cases.md` |
| 6 | 21 | 0 | `02-test-cases.md` |
| 7 | 96 | 0 | `02-test-cases-AT.md`, `-L.md`, `-T.md`, `-V.md` |
| 8 | 89 | 3 | `02-test-cases.md`, `-A.md`, `-AT.md`, `-P.md`, `-S1.md`, `-S2.md` |
| 8b | 43 | 2 | `02-test-cases.md`, `-AT.md` |
| 9 | 82 | 1 | `02-test-cases.md`, `-B.md`, `-W.md` |
| 9b | 13 | 0 | `02-test-cases.md` |
| 10 | 29 | 0 | `02-test-cases.md`, `-T.md` |
| 11 | 81 | 2 movidas a Inc 12 | `02-test-cases.md` |
| 12 | 8 | 0 | `02-test-cases.md` |

La precedencia es el orden natural `1a, 1b, 2 … 12`: para un ID repetido se toma la última definición de requisito, no una cita ni una tabla de reparto. `fold_canon.py` contiene la transformación; `fold-report.txt` y `fold-run.txt` archivan su ejecución.

## Fold y decisiones

- Se insertaron 329 IDs ausentes: 83 `R-A2L-LIST`, 24 `R-COPY`, 106 `R-PE-DEF`, 97 `R-PE-BENCH`, 17 `R-PE-EXPORT`, más `R-TUI-042a.3` y `R-HEX-EMIT-001.11`.
- Se reemplazaron 33 filas cuya versión activa posterior cambiaba la frase EARS. Se eliminaron del activo `R-TUI-063.2` y `R-TUI-063.7`.
- Los ocho IDs cuya última definición es withdrawn son `R-COPY.3`, `R-COPY.5`, `R-TUI-063.2`, `R-TUI-063.7`, `R-PE-DEF.1`, `R-PE-DEF.6`, `R-PE-DEF.7` y `R-PE-BENCH.2`. No tienen filas activas nuevas en el canon.
- `R-TUI-042a.2` y `.3` están retirados sólo en Inc 11 porque se mueven; la versión activa de Inc 12 es la plegada.
- Las familias ya plegadas, incluidas `R-A2L-MATCH`, `R-A2L-DEF`, `R-A2L-REFRESH`, `R-PICKER-CORRECT` y `R-A2L-READ`, se deduplicaron por ID. Sus textos activos coincidían con el canon y no recibieron una segunda definición.
- Las 15 menciones en negrita de Inc 10 bajo “Cited rows with cases here” son referencias de casos, no nuevas frases de requisito; sus requisitos ya existían y no se copió ese texto de prueba.
- Se consolidaron `CTX-A2L-LIST`, `CTX-COPY`, `CTX-PASTE`, `CTX-PE`, `CTX-PE-DEF`, `CTX-PE-BENCH`, `CTX-SAVEBACK` y el término `shown widget` de `CTX-SHELL`. Las enmiendas de Inc 8b sustituyen los términos correspondientes de Inc 8; las de Inc 9b amplían el bench. No se copiaron columnas de casos, controles negativos, Base ni resoluciones como requisitos.
- Dos frases se normalizaron para las reglas EARS existentes sin cambiar IDs ni semántica: `R-COPY.23` exige mostrar una instancia del diálogo con un solo `shall`; `R-PE-BENCH.29` conserva 0.5 s y 1.0 s en sus dos estados con un solo `shall` y deja fuera la resolución histórica. Estas formas están en `CANON_TEXT` del script.

## Trazas y chequeos

- `trace-before.txt`: invocación inicial errónea con `--req` repetido; `argparse` conservó sólo la última lista y por eso examinó únicamente Inc 9b. Se conserva para no confundirla con una pasada completa.
- `trace-before-all.txt`: pasada inicial completa, 752 activos, 10 withdrawn y 328 gaps de canon.
- `trace-final.txt`: pasada completa sobre el canon final, **0 gaps**.
- `static-reconciliation-final.txt`: 747 IDs finales de filas de requisito, 739 activos y 8 withdrawn; 0 duplicados, 0 filas mal formadas del batch y 0 diferencias de texto/forma contra la última definición aplicable. Nueve filas ajenas al batch contienen `|` literal y no fueron editadas.
- `ears-static-final.txt`: 363 filas plegadas/cambiadas (incluido un ID ancla citado en el informe), 0 errores de forma, apertura EARS, número de `shall`, cierre o segunda frase.
- `py_compile` de `fold_canon.py`: correcto. El bytecode generado se retiró de la evidencia.

La diferencia entre el conteo de `trace_check` y la reconciliación es mecánica: el parser también cuenta 15 referencias de casos de Inc 10 y marca globalmente como withdrawn los dos IDs movidos de Inc 11 a Inc 12. Por tanto: 739 activos de filas + 15 referencias − 2 movidos = 752; 8 withdrawn finales + 2 movidos = 10. La presencia de los dos requisitos activos de Inc 12 se comprobó por reconciliación aunque el parser los excluya del activo.

No se ejecutó pytest, la aplicación, probes de producto ni clipboard, conforme a la restricción local. No hay bloqueos restantes de CANON; la suite completa y sus law guards quedan no verificados en esta pasada.
