# Handoff — batch-103, Inc 6 → siguiente sesión

**Estado: INC 6 CERRADO, INTEGRADO Y PUBLICADO; BATERÍA COMPLETA EN CURSO.** No empezar otro incremento hasta recoger o registrar correctamente el estado de esa batería. G3 no es PASS: el resultado completo sigue pendiente.

## Referencias que gobiernan la reanudación

- Repositorio/rama central: `<HOME>\Github\s19_app-b103`, rama `batch-103`.
- Merge verificado de Inc 6: `c062293be6c122ecceca5701ea8afd0c6700f008`.
- Cierre documental y evidencia del merge: `96b28a495c65853c75d5063e032343426cb48b03`; ya publicado en `origin/main` con `git push origin batch-103:main`. Este handoff se añade en el commit siguiente, sin más cambios de producto.
- Resultados, limitaciones y pruebas: `.dev-flow/2026-11-05-batch-103/inc-6/04-validation.md` y `inc-6/REVIEW-PACKET.md`. No duplicar aquí las tablas.
- Plan y siguiente fila: `.dev-flow/2026-11-05-batch-103/PLAN.md`, Inc 1b (Clipboard: copy from every view). Los requisitos E1 ya existen en `inc-1b/`; E2–E4 siguen las dependencias del PLAN.
- Enmienda no bloqueante de la batería: `HANDOFF-2026-11-09-KIMI-BATCH-TO-MAIN.md`. Los findings van al siguiente batch; no convertir una corrida pendiente o fallida en PASS.

## Verificado al cerrar Inc 6

- Familia funcional: **77 passed**; histórica final: **304 passed**; mutantes: **21/21 killed**.
- Clon Linux detached del merge exacto `c062293b`: **77 passed in 387.08 s**, Inc 6 **0 gaps** y batch **0 gaps**. Evidencia: `evidence/inc-6/merge-functional.txt` y `merge-trace.txt`.
- Trazabilidad final central repetida tras el commit `96b28a49`: Inc 6 **1 US / 21 requisitos / 0 gaps**; batch **7 US / 381 requisitos / 0 gaps**.
- `.021/1-2` permanece **partial** deliberadamente: el handler síncrono está probado, la ruta montada `run_test` no. No reintentarla indefinidamente ni elevarla a full.
- Leyes: **550 passed, 3 skipped, 1 fallo heredado de redacción** en Inc 12 e `inc-2/steps.log`; el escaneo oficial de Inc 6 da **0 hits**. No alterar esos registros heredados para ocultar el fallo.
- La primera histórica dio 303/1 por una expectativa `u8` obsoleta. Se corrigieron sólo fixture y ledger al contrato de formato de Inc 6; la repetición completa dio 304/304. No hay defecto de producto abierto conocido de Inc 6.

## Batería completa activa — recoger antes de declarar G3

- Clon detached: `<USER>@<HOST>:/tmp/b103-inc6-merge-final`, commit `c062293b`.
- Launcher PID: **596133**. Runner: `evidence/full-suite/run_sequential.py`, **8 chunks secuenciales**, todos los `tests/test_*.py`.
- Log del launcher: `/tmp/b103-full-suite-launcher.txt`.
- Logs por chunk y resumen progresivo: `/tmp/b103-full-suite/chunk-NN.txt` y `/tmp/b103-full-suite/summary.json`. El directorio está deliberadamente fuera del repo para que las leyes no escaneen logs crudos.
- Comprobación:
  ```bash
  ssh -o BatchMode=yes <USER>@<HOST> \
    'ps -o pid,etime,time,stat -p 596133 || true; tail -20 /tmp/b103-full-suite-launcher.txt; cat /tmp/b103-full-suite/summary.json 2>/dev/null || true'
  ```
- Al terminar, `full_suite_exit=0` en el launcher y todos los `returncode` de `summary.json` deben ser 0 antes de llamar GREEN a la batería. Si hay fallos, conservar todos los chunks, diagnosticar el nodo concreto y derivar findings al siguiente batch según la enmienda.
- Copiar los artefactos a `evidence/full-suite/` sólo después de redactar identidades/rutas (`<HOME>`, `<HOST>`, `<USER>`); repetir el escaneo oficial. No editar los transcripts para borrar fallos.

## Canon y alcance del cierre

- `REQUIREMENTS.md` ya pliega los 381 requisitos activos de los incrementos implementados 1a/2/3/4/5/6/11/12: 15 sustituciones, 366 altas y retirada explícita de `R-A2L-004.5`. Las notas de contexto contradictorias del picker, tabla A2L y pestaña A2L de Patch también quedaron corregidas.
- La evidencia de trazabilidad de batch está en `evidence/full-suite/batch-trace.txt`.
- Inc 1b y Inc 10 no estaban implementados y no se plegaron como trabajo terminado. Sus artefactos E1 se conservan para su propia continuación.
- El worktree central conserva archivos auxiliares no rastreados de Inc 12: dejarlos intactos y no atribuirlos a Inc 6.

## Siguiente trabajo exacto

1. Recoger el estado real de la batería anterior y registrar/redactar su evidencia; no repetirla si ya terminó.
2. Reanudar **Inc 1b — Clipboard: copy from every view**, sin reabrir Inc 6 salvo evidencia de regresión.
3. Invocar `dev-flow` y `dev-flow-lessons`; usar `diagnose` para fallos difíciles y `review-packet` al cerrar el incremento. Para la batería, no declarar G3 PASS mientras haya fallos sin regla explícita.
4. Pruebas sólo en Linux con `s19ci`, HOME/XDG/LOCALAPPDATA neutros, stdin cerrado, bytecode deshabilitado y `.` insertado en `sys.path` antes de importar `s19_app`. Windows sólo análisis estático/`py_compile`, salvo la excepción ya aprobada de capturas.
5. No añadir ramas remotas ni iniciar Inc 10/7/8/9 en la misma sesión de Inc 1b.
