# Handoff — batch-103 Inc 1b, validación E5 exacta y pausa antes de WinCI

Fecha: 2026-11-12T21:09:55-06:00. Estado: **E5 SIGUE ABIERTO. La tarea de validación terminó y no hay procesos activos. No se ha hecho merge ni push de Inc 1b, no hay veredicto WinCI y no se ejecutaron mutantes de producto.** Este handoff cierra la sesión en stand by; no reanudar E1–E4 ni crear otro incremento.

## 1. Árbol y autoridad

- Worktree principal: `<HOME>\Github\s19_app-b103-inc1b-integration`.
- Rama: `b103-inc1b-integration`.
- HEAD: `305e5892adb4fb109ea204b5eb7c5d8beff151a4` (`batch-103 Inc 1b E5: record six-family green run`).
- **Todo el trabajo posterior a ese commit está sin commit**, incluidos producto/tests, nuevos guards, revisiones y evidencia. No usar `git reset --hard`, `git clean` ni `git checkout -- .`.
- Worktree WinCI: `<HOME>\Github\s19_app-b103-wci`, rama `b103-wci-2`, HEAD `49e776a4d2303e06002e6876d700dd4c71401167`, **limpio**. No se fusionó la rama de integración.
- Rama central `batch-103`: sigue en `29ce6448`; sus archivos auxiliares no rastreados deben quedar intactos.
- No hay tareas background activas al cerrar.

El clon Linux usado para el veredicto final fue construido desde la rama y `origin/main` locales, aplicando el diff y los untracked: `<RUNNER_HOME>/work/b103-inc1b-e5-exact2`. Para una nueva ejecución, reconstruir el clon desde el worktree local actual: después de ese clon se añadieron revisiones y la última redacción de evidencia.

La segunda exportación G2 sigue siendo `evidence/G2/veredicto-b103-r2.json`, SHA-256 `6eb12681c82727cfbbe5a21f6d88719b6ff3815ca0bd4d974c2f1274423ae6bf`. El addendum E5 de artefactos no añadió nodos ni casos; ver `inc-1b/E5-artifact-ruling.md`.

## 2. Resultados verificados

### Seis familias y selección E5

- Clon exacto, seis familias: **160 passed, 96 skipped en 1480.54 s**, exit 0.
  - Evidencia: `inc-1b/evidence-e5/full-six-families-final.txt`.
- Selección final E5: **246 passed, 2 skipped en 143.84 s**.
  - Incluye outer known-bad **14/14 RED** con auditoría de stdout, stderr y JUnit, 180 controles del escáner, el censo AST independiente y B97.
  - Evidencia redactada: `inc-1b/evidence-e5/final-targeted.txt` y `final-targeted-junit.xml`.

Estos resultados son Linux. No prueban WinCI, clipboard Windows real ni aceptación manual.

### Leyes, corrida final

Resultado: **671 passed, 3 skipped, 6 failed en 1665.99 s**. Evidencia redactada: `inc-1b/evidence-e5/laws-final.txt`.

Cinco fallos están probados como heredados mediante la misma selección ejecutada sobre `e2e93548` (base previa a E4) y `305e5892`:

- `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`;
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once`;
- `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors`;
- `test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach`;
- `test_b101_reach_and_reports_escape.py::test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go`.

La comparación produjo **5 failed / 1 passed en `e2e93548`**, **6 failed en `305e5892`** y **5 failed / 1 passed en el recheck posterior al arreglo B97**. No se corrigieron esos cinco defectos ajenos ni se ocultaron registros antiguos. Detalle: `inc-1b/E5-law-rulings.md` y `evidence-e5/law-recheck.txt`.

**Pendiente de diagnóstico:** `tests/test_b97_key_bar.py::test_tc_b97_69_page_keys_do_nothing_where_disabled` terminó en `did not settle: A2L loaded`. Es un nodo distinto del B97 corregido. **No está clasificado como heredado ni flaky.** Para llamarlo flaky se exige la medición de la clase (misma base, N≥10, tasa registrada); no se hizo esa investigación antes de la pausa.

### Regresión B97 cerrada

`test_tc_b97_72_clicks_run_the_action_and_type_nothing` pasaba en `e2e93548` y fallaba tras cambiar `q` a `help_quit`. El oráculo se actualizó para la regla aprobada: clic en `q Quit` → `action_help_quit=1`, `action_quit=0`, input vacío y sin `simulate_key`. El producto conserva Ctrl+Q/palette Quit inmediatos (R-COPY.24). Revisión: `inc-1b/E5-final3-review-laws.md`.

## 3. Revisiones y correcciones principales

- Transporte/holders: **GO estático** en `E5-final2-review-transport.md`.
  - PowerShell de producto y helper usa stdin/stdout binarios y UTF-8 explícito, sin `text=True`, BOM ni normalización universal de saltos.
  - Reader conserva CR/CRLF/LF final y `"" → None`; writer usa `ReadToEnd()` + WPF `SetText`.
  - Readers directos se separan del pegado en `Input` (sólo primera línea).
  - Holders: guardas antes de proceso/Win32, readiness acotada, kill/wait/cierre/joins/poll final y controles de fallos; no se acepta cleanup con procesos vivos.
- Aislamiento/procesos: **GO estático** en `E5-final2-review-isolation.md`.
  - Seeds externas con `PresentationCore`, Base64, Unicode/CR/LF/LF final, PowerShell absoluto y decoys en todos los launchers.
- Gate WinCI: WG-01…03 cerrados estáticamente.
  - `tests/support/b103_winci_manifest.json`: 256 nodeids, 108 obligaciones (46 views/25 tail/9 quit/28 AT), 28 AT = 14 P1 + 14 P2.
  - Partición WinCI escrita, no ejecutada: **212 passed + 44 skipped** (37 legacy + 6 Linux-only + AT-I1b-8 manual).
  - Gate exige resultados passed, ausencias/duplicados/extras como violación, skips exactos y reconciliación JUnit.
- Divulgación: D-01…D-06 cerrados tras `E5-fix3-disclosure.md`.
  - 18 familias de canarios, censo AST que descubre valores no declarados y 180 known-bad por familia/forma/superficie.
  - Escáner fail-closed antes de upload; artefactos sólo si `artifact_safety` termina success.
  - Addendum de diseño: `E5-artifact-ruling.md` y sincronía en `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc1b.md`.
- Evidencia: **GO** en `E5-final4-review-evidence.md` para F3-01/D-04, con las correcciones posteriores descritas abajo.

## 4. Redacción e integridad final

Última verificación local:

- `redact_e5.py --check`: **PASS, 161 archivos, residual=0, 8 excepciones declaradas** en tres controles ejecutables.
- `refresh_manifests.py --check`: **PASS, 6 manifests / 83 archivos**; raíz con 25 entradas.
- La ordenación es determinista multiplataforma mediante `path.name`; los manifests se verificaron en Windows y Linux antes de las últimas adiciones.
- Se añadieron reglas para `pytest-of-<cuenta>` y directorios neutros de estado; known-present del redactor quedó en **17/17** al añadir esas dos familias (16/16 antes del directorio neutro).
- `evidence-e5/redaction-final.txt` es el recheck de la ley con bytes corregidos: sigue fallando sólo por registros heredados E2/E3/E4; la búsqueda específica sobre `inc-1b/E5*` e `inc-1b/evidence-e5/**` da **0 hits nuevos**.
- No se modificaron los registros heredados para ocultar el fallo.

Después de crear nuevos transcripts en la próxima sesión, repetir `redact_e5.py`, su `--check` y `refresh_manifests.py --check`; los conteos cambiarán.

## 5. Cambios sin commit que deben conservarse

### Producto/configuración

- `s19_app/tui/os_clipboard_input.py` — transporte binario exacto, readers/writers PowerShell y comportamiento asociado.
- `.github/workflows/clipboard-windows.yml` — seis familias, Textual 8.2.8, paths explícitos, JUnit, gate, escáner y upload condicionado, exits preservados.

### Tests y soporte

- `tests/support/b103_clipboard.py` — seed/read externas binarias, guards, captura completa de logs y `_ProbeDetail`.
- `tests/support/b103_winci_gate.py`, `b103_winci_manifest.json` — censo/gate WinCI.
- `tests/support/b103_artifact_safety.py` — escáner de artefactos.
- `tests/test_b103_clipboard_tail.py`, `test_b103_clipboard_windows.py`, `test_b103_copy_paste_matrix.py`, `test_b103_copy_quit_dialog.py` — rutas reales, holders, transporte, waits, seeds y timings.
- Nuevos `tests/test_b103_e5_safety.py` y `tests/test_b103_winci_gate.py` — outer/gate/escáner/censo.
- Contratos actualizados: `tests/test_b102_clipboard.py`, `test_loadfilescreen_input.py`, `test_b103_clipboard_core.py`, `test_b97_key_bar.py`, `test_id_registry.py`.
- `EXPECTED_SCANNED_TEST_FILES = 307`: 303 archivos en HEAD + cuatro nuevos módulos `.py` (dos tests y dos soporte); el JSON no cuenta.

### Registros y evidencia

- `inc-1b/01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc1b.md` — addendum de artefactos.
- `inc-1b/E5-*.md` — correcciones, reviews y rulings; leer primero los citados en este handoff.
- `inc-1b/evidence-e4/{matrix,tail}/SHA256SUMS` — conservados; `git diff --check` aún señala trailing whitespace en la primera línea de ambos.
- Todo `inc-1b/evidence-e5/`, incluidos runners, transcripts redactados, manifests, censo AST, mutantes y baseline WinCI anterior.
- `inc-1b/evidence-e5/previous-winci-failures.txt` — ejecución WinCI anterior: **17 failed / 60 passed / 37 skipped**; sirve sólo como baseline de comparación.

## 6. Próximos pasos exactos al reanudar

1. **Diagnosticar `test_tc_b97_69`** antes de declarar las leyes cerradas. No etiquetarlo flaky/heredado sin medición; B97-72 sí está corregido.
2. Actualizar y revisar `E5-mutant-plan.md` y su manifiesto antes de ejecutar nada:
   - Las exclusiones antiguas 9/10 sobre seeds quit recorder y hostile simulado ya no describen el árbol actual.
   - Añadir controles de producto para la regresión a `text=True` y para pérdida de LF/CRLF; revisar si el total pasa de 71 a 73 en vez de conservar el número por conveniencia.
   - El baseline actual de las cuatro familias nuevas es **123 passed / 19 skipped** (142 nodos); las seis familias dan 160/96 (256). El antiguo 122/19 y las afirmaciones 141/218 son históricos.
   - Revalidar anchors, selectores y baseline en el árbol actual. GC-C14 sigue pendiente/BAD hasta tener timeout y workers/iteraciones con captura override/tail.
3. Repetir revisión independiente final si cambia el plan o el código; conservar la evidencia actual sin reejecutar baterías sin causa nueva.
4. Preparar WinCI sólo tras resolver los puntos anteriores y redacción:
   - fusionar `b103-inc1b-integration` en el worktree limpio `b103-wci-2`, sin forzar ni borrar historia;
   - revisar el diff y realizar el push autorizado para CI;
   - seguir `clipboard-windows` con `gh` y comparar con los 17 fallos baseline;
   - exigir el gate de 256 nodos/108 obligaciones; no aceptar skips de infraestructura ni P2 como verificados.
5. Ejecutar los mutantes Linux en copias del árbol y los cuatro WinCI en CI, con baseline por grupo, `applied_count=1`, restore SHA-256, bytecode deshabilitado y verdicts KILLED/SURVIVED/CRASH/BAD.
6. Después: actualizar ledger/canon con resultados reales, cobertura independiente, capturas reales 118×54 y 220×60, `04-validation.md`, `REVIEW-PACKET.md` y trazabilidad. AT-I1b-8 permanece manual para el operador.

## 7. Reglas de ejecución para la próxima sesión

- Invocar `dev-flow` y `dev-flow-lessons`; `diagnose` para B97-69 y fallos difíciles; `review-packet` al cerrar el incremento; `tui-design` para capturas.
- Pytest/probes sólo en Linux `s19ci`; Windows local sólo lectura estática/`py_compile` y capturas ya autorizadas. Nada de clipboard real en el PC del operador.
- HOME/XDG/LOCALAPPDATA/TMPDIR aislados con un identificador que no aparezca en el corpus. No usar `home` ni `neutral` como basename: el guarda los adopta como identidades.
- stdin cerrado, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, pytest cache deshabilitado y `.` antes de importar `s19_app`; imprimir `s19_app.__file__` en cada transcript.
- Para leyes, usar un clon exacto del HEAD local más diff/untracked. No reutilizar `pre-ci2`: contenía módulos ajenos y produjo resultados inválidos para el entregable.
- No cambiar producto/tests durante una batería. Leer transcript final y exit code, no la mera existencia del proceso.
- Redactar antes de publicar cuentas, hosts, IP, rutas personales, nonces y canarios; recalcular manifests desde los bytes almacenados.

## 8. Lectura recomendada primero

1. `inc-1b/E5-law-rulings.md` — leyes, base heredada y B97.
2. `inc-1b/E5-final2-review-transport.md` y `E5-final2-review-isolation.md` — GO estáticos.
3. `inc-1b/E5-final3-review-disclosure.md` y `E5-final4-review-evidence.md` — cierre de divulgación/evidencia.
4. `inc-1b/E5-artifact-ruling.md` — por qué se permite upload sólo tras escáner.
5. `inc-1b/evidence-e5/{full-six-families-final.txt,final-targeted.txt,laws-final.txt,redaction-final.txt}` — resultados reales.
6. `inc-1b/E5-mutant-plan.md` y `evidence-e5/mutants/VALIDATION.md` — estado histórico que debe actualizarse antes de mutantes.

**Fin de la sesión en stand by.**
