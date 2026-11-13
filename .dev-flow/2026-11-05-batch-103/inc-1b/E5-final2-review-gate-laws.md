# E5 — Revisión independiente FINAL2 de gate, workflow y leyes

Base revisada: HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` más el working tree actual. Alcance limitado a WG-01…WG-03, sus correcciones posteriores y los cambios nuevos en `.github/workflows/clipboard-windows.yml`, `tests/test_b103_clipboard_core.py`, `tests/test_b102_clipboard.py`, `tests/test_loadfilescreen_input.py`, `tests/test_id_registry.py`, `tests/test_b103_copy_quit_dialog.py` y la sincronía del addendum en `01-requirements.md`, `02-test-cases.md` y `codewire/graph-inc1b.md`.

Revisión independiente estática. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow, WinCI ni mutantes; tampoco hice mutaciones Git ni modifiqué producto, tests, workflow, ledger, canon o evidencia. Usé lecturas acotadas, búsquedas, `git diff/status/diff --check` y censos read-only de nombres de archivos. La selección Linux exacta **164 passed / 2 skipped** es un resultado comunicado por orquestación, no una ejecución repetida por mí. El full de las seis familias y las leyes sigue corriendo en otro clon exacto y todavía no aporta un resultado a esta revisión.

## Veredicto

**NO-GO para cerrar E5 o declarar cobertura WinCI por esta área.**

La implementación escrita de WG-01…WG-03 se conserva y las correcciones nuevas son estáticamente coherentes. No encontré un defecto MAJOR/HIGH nuevo directamente introducido por esas correcciones. Persiste el bloqueo de evidencia **WINCI-RUN** y aún deben llegar el resultado full actual y la evidencia de mutantes de producto. Las rutas escritas y el GREEN Linux comunicado no son WinCI.

Quedan además dos hallazgos **MINOR · impl**, documentales y no bloqueantes: la procedencia del contador 307 está mal descrita y dos referencias de línea del addendum quedaron desplazadas. No cambian el comportamiento del gate ni el valor correcto del oracle.

## Bloqueo que permanece

### WINCI-RUN — HIGH · design-gap (evidencia) — sigue sin ejecución ni veredicto WinCI

La ruta actual está escrita en `.github/workflows/clipboard-windows.yml:79-133`, pero no se ha aportado una ejecución Windows real con `WINCI_GATE_RESULT PASS`. El gate conserva la población y los outcomes necesarios (`tests/support/b103_winci_gate.py:343-440`) y la prioridad del exit de pytest (`:458-493`), pero ese código no es evidencia de que el runner haya pasado.

El desbloqueo requiere los artefactos reales de pytest, JUnit, gate y seguridad, con `pytest_exit=0`, `gate_exit=0`, **256 testcases = 212 passed + 44 skipped**, **108/108 obligaciones**, **28/28 AT**, **14/14 P1 y 14/14 P2**, sin nodos ausentes, extras, duplicados ni skips no permitidos. La selección Linux 164/2 no demuestra esas cifras ni ejecuta PowerShell/clipboard reales.

El full de las seis familias y leyes del mismo árbol debe terminar y evaluarse antes del cierre. Tampoco hay mutantes de producto ejecutados: no atribuyo mortalidad a los controles Linux ni a los self-tests del harness.

## WG-01…WG-03: cierre estático conservado

### WG-01 — población y obligaciones

- El manifiesto sigue declarando 256 testcases, 108 obligaciones, 212 passed y 44 skipped (`tests/support/b103_winci_manifest.json:4-17`).
- El cargador exige las seis familias, nodeids únicos, obligaciones únicas dentro de la población y no eximidas, y rederiva los totales (`tests/support/b103_winci_gate.py:239-289`). La desagregación sigue siendo 46 views + 25 tail + 9 quit + 28 AT = 108.
- `tests/test_b103_copy_quit_dialog.py` conserva 28 funciones de test. Las seis marcas nuevas no cambian nombres, parametrizaciones, outcomes esperados ni el `expected_count: 28` de quit (`tests/support/b103_winci_manifest.json:277-280`).
- El audit rechaza nodos ausentes, extras y duplicados y exige `passed` para cada obligación (`tests/support/b103_winci_gate.py:397-434`).

### WG-02 — skips exactos

- La exención sigue indexada por nodeid y exige la razón literal; un skip no declarado, una razón distinta o un skip esperado que pasa producen violación (`tests/support/b103_winci_gate.py:379-394`).
- La partición WinCI esperada permanece en 6 Linux-only + 37 legacy-linux-h + 1 manual = 44. No se convirtió ningún skip escrito en un PASS.
- AT-I1b-8 continúa siendo el único skip manual y está fuera de las 108 obligaciones (`tests/support/b103_winci_manifest.json:260-265,359-364`). Su test sigue marcado para no ejecutarse en automatización (`tests/test_b103_copy_paste_matrix.py:437-444`). **No lo marco verificado:** requiere la aceptación manual separada del operador, 6/6.

### WG-03 — AT, JUnit y salida

- Los IDs AT, la relación celda/target/ruta y las particiones se validan en `tests/support/b103_winci_gate.py:201-214,247-258`; el audit exige AT passed y P1/P2 completos en `:411-434`.
- Los contadores `tests`, `skipped`, `failures` y `errors` se reconcilian en `:321-340,436-439`; outcomes ambiguos, failures y errors no se aceptan (`:362-399`).
- Un pytest distinto de cero conserva prioridad como exit incluso si el XML o manifiesto es ilegible; con pytest 0, cualquier violación produce gate 1 (`:465-493`).

## Workflow y addendum de artefactos

### Paths, escáner, upload y exit

- Las dos rutas explícitas `s19_app/tui/os_clipboard_input.py` y `s19_app/tui/capped_text_area.py` están en **ambos** filtros: `push.paths` (`.github/workflows/clipboard-windows.yml:10-11`) y `pull_request.paths` (`:31-32`). El glob de producto se conserva (`:12,33`). El guarda legacy las sigue exigiendo (`tests/test_b103_clipboard_core.py:1737-1745`).
- Pytest y gate capturan `$LASTEXITCODE` inmediatamente y el step sale con `$gateExit` (`.github/workflows/clipboard-windows.yml:91-98`). `continue-on-error` se limita a ese step (`:83-86`).
- El escáner está antes del único upload (`:100-115`). El upload exige literalmente `always() && steps.artifact_safety.outcome == 'success'` y `if-no-files-found: error` (`:113-123`). El guarda actualizado exige una sola acción v4, el orden escáner → upload y ambas condiciones (`tests/test_b103_clipboard_core.py:1752-1758`); el oracle parcial adicional está en `tests/test_b103_winci_gate.py:426-432`.
- El step final falla cerrado si falta `WINCI_GATE_EXIT` y en otro caso sale con ese valor (`.github/workflows/clipboard-windows.yml:125-133`). Un fallo funcional con artefactos limpios permite conservar evidencia sin volver verde el job; un fallo del escáner impide upload y mantiene el job rojo; un fallo de upload tampoco se convierte en éxito.

### Sincronía 01/02/graph y alcance del ruling

El reemplazo limitado de la antigua prohibición Inc 1a está formalizado en `E5-artifact-ruling.md:7-25`: sólo se permite evidencia WinCI auditada, tras escáner exitoso y preservando el fallo funcional. La misma barrera aparece de forma coherente en:

- `01-requirements.md:131`, contexto ampliado de R-TUI-043.13/102, sin nueva fila ni cambio de conteos;
- `02-test-cases.md:127`, Expected y oracle estático **partial** de la misma case, y nota `:206`, que conserva explícitamente el `verified` histórico sin presentarlo como ejecución del addendum;
- `codewire/graph-inc1b.md:203`, ejemplo existente /102, sin nodo nuevo.

No hay cambios frente a HEAD bajo `.dev-flow/2026-11-05-batch-103/inc-1a`. El addendum no autoriza otros uploads ni declara publicación real. Estas comprobaciones son estáticas: el escáner y el upload reales siguen cubiertos por WINCI-RUN.

## Correcciones legacy y leyes afectadas

### Contratos PowerShell legacy

- `tests/test_b102_clipboard.py:570-634` modela stdout binario y exige CRLF preservado, `Out.Write((Get-Clipboard -Raw))`, ausencia de `Out.WriteLine` y de modo texto/newline universal. El writer usa UTF-8 bytes por stdin, `ReadToEnd` + WPF `SetText`, y rechaza `Set-Clipboard` (`:637-709`).
- `tests/test_loadfilescreen_input.py:463-521` conserva Unicode y CRLF y espera U+FFFD sólo para el byte inválido, sin restaurar `rstrip` ni `encoding`/`errors` de `subprocess`.
- Esos oráculos concuerdan con la captura/decodificación binaria actual (`s19_app/tui/os_clipboard_input.py:307-340`) y con stdin UTF-8 binario (`:454-464`). No encontré un fake `str` residual en los usos de `_FakeCompleted` ni un cambio de nodeid en estas correcciones. La concordancia estática no es una ejecución PowerShell.

### `serial_timing` y `report_margin`

- Hay exactamente seis decoradores directos nuevos: `tests/test_b103_copy_quit_dialog.py:630,641,656,861,877,990`, sobre los seis nodeids ya existentes `:631,642,657,862,878,991`.
- `_answer_and_time` conserva `timing_bound(1.0)` y ahora pone `report_margin(label, elapsed, bound)` directamente como límite de la comparación (`:451-460`). `report_margin` registra y devuelve el mismo bound (`tests/support/timing.py:71-81`), por lo que no se relaja el umbral.
- La ley de marcas rechaza tanto brazos sin marca como marcas en no-brazos (`tests/test_suite_hygiene.py:264-270,392-403`), y la ley de margen exige que no queden upper bounds sin reporte (`:273-278,1451-1453`). La selección comunicada incluye ambas leyes y el corpus (`evidence-e5/run_e5_final_targeted.py:23-25`), pero el comportamiento de las seis familias completas espera el full en curso.

### Corpus 307

`EXPECTED_SCANNED_TEST_FILES = 307` está en `tests/test_id_registry.py:214` y el guarda compara ese valor con el corpus real en `:549-574`. Dos censos read-only independientes —filesystem `tests/**/*.py` y `git ls-files`, ambos con las cuatro exclusiones de `tools/id_registry.py:259,295-323`— dieron **307** en el working tree. El valor ejecutable es, por tanto, correcto.

## Hallazgos menores directamente introducidos

### DOC-01 — MINOR · impl — la procedencia escrita de 307 no coincide con HEAD

`tests/test_id_registry.py:211-213` afirma que HEAD tenía 305 archivos, que 299 estaba seis por detrás y que sólo se añaden dos módulos. El censo read-only de `git ls-tree -r --name-only HEAD tests`, aplicando las mismas extensiones/exclusiones, da **303**, no 305. El delta real hasta 307 es **+4**: `tests/test_b103_e5_safety.py`, `tests/test_b103_winci_gate.py`, `tests/support/b103_artifact_safety.py` y `tests/support/b103_winci_gate.py`.

Esto no invalida el valor 307 ni el GREEN comunicado de TC-607; sí hace falso el historial local del ajuste. Cuando se permita editar, debe corregirse sólo ese comentario, no la constante ni el oracle.

### DOC-02 — MINOR · impl — rangos de workflow desplazados en el addendum

`E5-artifact-ruling.md:25` cita la secuencia completa como `.github/workflows/clipboard-windows.yml:98-131`; `E5-fix2-workflow-law.md:31` usa `:98-121` y `:123-131`. En el árbol revisado, escáner, upload y preservación de exit están respectivamente en **`:100-111`, `:113-123` y `:125-133`**. La regla semántica y 01/02/graph sí están sincronizados; sólo las referencias editoriales quedaron cortas/desplazadas.

## Condiciones para cambiar el veredicto

1. Recibir el full actual de las seis familias y las leyes en el clon exacto y evaluar cualquier fallo sin relajar guardas.
2. Ejecutar WinCI real y obtener los artefactos y el resultado exacto exigidos por WINCI-RUN, con escáner previo, upload condicionado y exits preservados.
3. Ejecutar y registrar por separado los mutantes de producto previstos; ninguno se da por ejecutado aquí.
4. Mantener AT-I1b-8 como manual pendiente hasta la aceptación del operador; no deducirla del gate automatizado.

Los dos MINOR pueden quedar como corrección documental no bloqueante. Ninguna parte de este informe convierte las rutas escritas, el 164/2 Linux o los self-tests en evidencia WinCI, full actual, mutantes de producto o AT-I1b-8 verificada.
