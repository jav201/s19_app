# Handoff — batch-103 Inc 1b, E5 antes de WinCI

Fecha: 2026-11-12T14:51:46-06:00. Estado: **E4 CERRADO; E5 EN CURSO. No hay veredicto E5 ni WinCI ejecutado.** Continuar en el worktree de integración; no reiniciar E1–E4 ni crear otro incremento.

## Dónde continuar y autoridad de los registros

- Worktree activo: `<HOME>\Github\s19_app-b103-inc1b-integration`, rama `b103-inc1b-integration`, HEAD `0d4d4e7c800b27040769a1a10117e62884cc7326`.
- Leer primero, de forma selectiva:
  - `.dev-flow/2026-11-05-batch-103/inc-1b/steps.log` (historial E1–E5).
  - `inc-1b/E4-ledger-audit.md` — PASS y conteos vigentes.
  - `inc-1b/E5-winci-review.md`, `E5-pre-ci-review.md`, `E5-pre-ci-security.md` — hallazgos cuyas correcciones ya se aplicaron; aún falta re-review.
  - `inc-1b/E5-mutant-plan.md` y `E5-mutant-plan-review.md` — 71 controles, selectores corregidos.
  - `inc-1b/evidence-e5/mutants/VALIDATION.md` — runner y self-test del harness.
- El veredicto G2 vigente es la **segunda exportación**, `evidence/G2/veredicto-b103-r2.json`, SHA-256 `6eb12681c82727cfbbe5a21f6d88719b6ff3815ca0bd4d974c2f1274423ae6bf`. La primera queda sólo como histórica. No usar las decisiones A/q anteriores.
- Grafo aprobado: `inc-1b/codewire/graph-inc1b.md`, 24 nodos únicos. Requisitos: 23 activos, 112 casos.

## Commits y otros worktrees

- Integración actual: `0d4d4e7c` más todos los cambios E5 **sin commit** enumerados abajo.
- Rama central `batch-103` en `<HOME>\Github\s19_app-b103`: `29ce6448`; contiene producto/tests E4, pero no los últimos cierres E4/E5. Sus archivos auxiliares no rastreados de `inc-12/` deben quedar intactos.
- `s19_app-b103-inc1b-code`: `63f2bff0`, limpio.
- `s19_app-b103-inc1b-tests`: `f5f910ab`, limpio.
- No se ha hecho push de Inc 1b. `origin/main` seguía en `dc44b364` al comenzar esta fase.

## Batería E5 completa — finalizada

La ejecución que estaba activa al escribir el handoff terminó correctamente a los 1453 s. **No repetirla sin una causa nueva.**

- Resultado: **160 passed, 96 skipped in 1449.12 s**, exit 0, sin fallos, sobre **218 nodos** (141 nuevos + 77 heredados Windows).
- Los 96 skips incluyen los 19 brazos ya conocidos y los 77 tests heredados Windows-only en Linux; no son cobertura WinCI ni verificación de esos brazos.
- Árbol remoto: `/home/<USER>/work/b103-inc1b-e5-pre-ci2`.
- Evidencia local redactada: `inc-1b/evidence-e5/full-six-families.txt`, con identidades sustituidas y manifests refrescados por `redact_e5.py` / `refresh_manifests.py`.
- La batería ya no tiene proceso activo. El resultado confirma el GREEN Linux, pero no es veredicto WinCI ni cierre E5.

## Verificado antes del handoff

- E4: GREEN `e8f8e3d1` = **122 passed, 19 skipped**. Ledger audit PASS: 32 covered / 76 partial / 4 gap; 108 verified / 4 not_run; P1 14 partial verified; P2 14 not_run; AT-I1b-8 manual not_run.
- Pre-CI posterior a readiness inicial: otra ejecución **122 passed, 19 skipped**.
- Transporte PowerShell: `test_e5_powershell_preserves_lf_and_emits_bom_free_readers` = **1 passed en Linux**, transcript `inc-1b/evidence-e5/powershell-static-green.txt`.
- Mutantes: harness validado estáticamente y self-test de cuatro veredictos/restores PASS. **0 mutantes de producto ejecutados.**
- No hay resultado WinCI, AT-I1b-8 ni cobertura completa declarada.

## Cambios sin commit que deben conservarse

En el worktree de integración:

- `s19_app/tui/os_clipboard_input.py` — PowerShell `ReadToEnd()` + `.NET SetText($text)`; lectura `UTF8Encoding($false)` + `Out.Write`, sin BOM ni LF añadido.
- `.github/workflows/clipboard-windows.yml` — seis familias, Textual 8.2.8, JUnit/artefacts y gate.
- `tests/support/b103_clipboard.py` — espera tail, lectura Base64 exacta, seed externa y guards.
- `tests/support/b103_winci_gate.py` — nuevo gate JUnit que preserva pytest exit y rechaza skips no permitidos.
- `tests/test_b103_clipboard_tail.py` — holder, esperas, rutas reales R-TUI-043.13/101-102, exact LF, logs sanitizados.
- `tests/test_b103_clipboard_windows.py` — holder heredado y anti-PATH decoy.
- `tests/test_b103_copy_paste_matrix.py` — esperas, seed externa y gate de 28 celdas.
- `tests/test_b103_copy_quit_dialog.py` — 9 rutas WinCI reales para R-COPY.16/.20.
- `inc-1b/E5-mutant-plan.md`, `E5-mutant-plan-review.md`, `E5-winci-review.md`, `E5-pre-ci-review.md`, `E5-pre-ci-security.md`, `E5-powershell-fix-brief.md`.
- `inc-1b/evidence-e4/{matrix,tail}/SHA256SUMS`, `manifest-refresh-pre-ci.txt`, `redaction-pre-ci-e5.txt`.
- Todo `inc-1b/evidence-e5/` y `pi-e5-powershell-fix.txt`.

No descartar estos archivos ni usar `git reset --hard`, `git clean` ni `git checkout -- .`. Los cambios fueron validados por familias, pero aún falta la batería completa y las revisiones finales.

## Próximos pasos exactos

1. Usar el tally final **160 passed / 96 skipped** y la evidencia `full-six-families.txt`; no repetir la batería salvo cambio de producto/tests o una discrepancia que deba diagnosticarse.
2. Revisar los cambios E5 con arquitectura y seguridad independientes. Las revisiones anteriores eran NO-GO antes de las últimas correcciones; no reutilizar ese veredicto como si fuera actual.
3. Ejecutar las leyes del proyecto en Linux: `test_engine_unchanged`, `test_tui_directionb`, `test_suite_hygiene`, `test_requirements_canon`, `test_id_registry`, `test_address_census`, `test_filename_markup_safety`, `test_report_markup_safety`, `test_b101_reach_and_reports_escape`, `test_b97_key_bar`, `test_tui_patch_json`, `test_b102_clipboard`, `test_clipboard_tk_singleton`, `test_loadfilescreen_input`. Conservar el fallo heredado de redacción; no alterar registros antiguos para ocultarlo. Verificar explícitamente 0 hits nuevos en Inc 1b.
4. Sólo después de GREEN + leyes + re-review + redacción, preparar WinCI. Reutilizar la rama existente `b103-wci-2` en `<HOME>\Github\s19_app-b103-wci` en lugar de crear una rama remota nueva; revisar su estado y fusionar `b103-inc1b-integration` antes del push autorizado para CI. No forzar ni borrar historia.
5. Ejecutar/seguir `clipboard-windows` con `gh`. Comparar fallos con la ejecución previa; un GREEN local no es veredicto de CI. No aceptar skips de infraestructura ni P2 como verificados. AT-I1b-8 queda manual para el operador.
6. Ejecutar los 67 mutantes Linux en copias del árbol y los 4 WinCI en CI. `GC-C14` sigue pendiente/BAD hasta acotar tiempo y workers/iteraciones con captura override/tail; no llamarlo killed ni survivor. Baseline por grupo, `applied_count=1`, restore SHA-256, bytecode deshabilitado y veredictos KILLED/SURVIVED/CRASH/BAD.
7. Actualizar ledger/canon con resultados reales, repetir code/security review y cobertura independiente. Tomar capturas reales del diálogo y avisos a 118×54 y 220×60; no usar el prototipo como prueba de producto.
8. Escribir `04-validation.md` y `REVIEW-PACKET.md` con `review-packet`, verificar trazabilidad y sólo entonces integrar/fast-forward central y entregar `main` según la autorización existente. No iniciar Inc 10/7/8/9 en esta sesión de Inc 1b.

## Reglas de ejecución y modelos

- Invocar `dev-flow` y `dev-flow-lessons`; `diagnose` para fallos difíciles; `review-packet` al cerrar; `tui-design` para la revisión visual.
- Kimi 2.8 en swarm para diseño/revisión/integración. DeepSeek v4 Pro o Flash con esfuerzo apropiado para implementación mecánica, mutantes, evidencia y records, siempre detrás de tester/revisor independiente. `--thinking max` existe, pero una pasada anterior agotó 300 s sin veredicto; no confundir timeout con PASS.
- Pytest/probes sólo en Linux `s19ci`, HOME/XDG/LOCALAPPDATA neutros, stdin cerrado, bytecode deshabilitado y `.` antes de importar `s19_app`; imprimir `s19_app.__file__` en cada transcript. Windows sólo estático/`py_compile` y capturas aprobadas.
- No clipboard real en el PC del operador. WinCI únicamente en runner desechable/aislado. No registrar cuentas, hosts, IP, rutas personales ni payloads secretos en evidencia; usar placeholders y manifests recalculados.
- No modificar producto mientras una batería esté activa. No confundir un proceso existente con su resultado: leer el transcript final y exit code.
