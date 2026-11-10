# Handoff — batch-103, continuar la batería hasta `main`

Fecha: 2026-11-09. Proyecto: `<repo>` (`s19_app-b103`).

## Orden vigente del operador

> Sigue con el incremento, la batería ba hasta que todos los incrementos estén en el main

Interpretación operativa: continuar los incrementos restantes, uno por uno, sin detener la batería después de cada review packet. El operador ya dio aprobación general para avanzar hasta integrar todos los incrementos en `main`. Las decisiones visuales, de alcance y las compuertas G2/G3 que requieran al operador siguen siendo obligatorias; esta orden no autoriza omitir pruebas ni relajar requisitos.

### Enmienda del operador, 2026-11-10: suite completa no bloqueante después de Inc 6

Después de Inc 6 se ejecutará la batería completa, pero su resultado **no bloqueará la integración ni el push a `main`**. El operador autoriza expresamente ese push sin esperar el resultado y pide continuar las implementaciones; los findings de la batería se registrarán para el siguiente batch. Las compuertas E1–E5 de cada incremento, la trazabilidad y la verificación del clon de cada merge siguen siendo obligatorias. No se declarará la suite completa GREEN ni el batch integralmente validado mientras su corrida esté pendiente o tenga fallos sin resolver; esta excepción de secuencia no elimina la evidencia ni convierte G3 en un PASS.

## Estado al cerrar esta sesión

- **Inc 12 está cerrado e integrado localmente en `batch-103`.** No repetir su implementación ni sus compuertas.
- `batch-103` local: `a989c9f9` (`batch-103 Inc 12 E5: close increment record`).
- Merge de Inc 12: `edba3c15`.
- `b103-inc12-integration`: `b5a71f5a`, publicada en `origin` con autorización expresa.
- `main` no fue modificado. `batch-103` no fue publicada en esta sesión.
- El worktree de integración quedó limpio. El hogar central conserva transcripts auxiliares `pi-*.txt` y `evidence-e5-trace-central.txt` no rastreados, encontrados al reconciliar; se dejaron intactos, no barrerlos ni atribuirlos a trabajo nuevo.

Estado y evidencia de Inc 12, no copiar aquí:

- `.dev-flow/2026-11-05-batch-103/inc-12/04-validation.md` — **PASS-WITH-NOTES**.
- `.dev-flow/2026-11-05-batch-103/inc-12/steps.log` — historial E1–E5 y cierre.
- `.dev-flow/2026-11-05-batch-103/inc-12/evidence-e5/OPERATOR-VERDICT.md` — aprobación visual.
- `.dev-flow/2026-11-05-batch-103/inc-12/evidence-e4-green-final7.txt` — **112 passed in 811.67 s** sobre `1a907685`.
- `.dev-flow/2026-11-05-batch-103/inc-12/evidence-e5-snapshot-verify-log.txt` — **29 passed, 4 deselected** en CI canónico.
- Después del merge se comprobó que `s19_app` y `tests` no diferían del árbol validado y que `trace_check.py` seguía con **0 gaps**.

Notas que pasan al batch, ya registradas en `04-validation.md`:

- Timing grande case-06: 1.372 s aislado frente a 1.000 s; base 1.399 s. Preexistente, no clasificado *flaky*.
- Dos snapshots Patch ya fallaban en base y no fueron cambiados por Inc 12.
- La suite completa del repositorio y el fold al canon quedan para el cierre del batch.

## Próximo incremento

**Inc 2b — escritura del modelo escalar A2L:** codificar valores y aplicarlos a la imagen usando el lector corregido por Inc 11.

Leer primero, de forma selectiva:

1. `.dev-flow/2026-11-05-batch-103/PLAN.md`, especialmente la división 2a/2b y el orden posterior.
2. Los registros existentes de Inc 2/Inc 2a y sus rulings; localizar las secciones 2b con Grep, no releer archivos grandes completos.
3. Los contratos I-2 y las interfaces ya aprobadas. No reabrir decisiones cerradas salvo evidencia nueva.

Orden restante conocido: **2b/3b, 5, 6**, después **1b/10/7/8/9** según G2. Reconciliar este orden con `PLAN.md` y los artefactos antes de empezar; no asumir que un incremento carece de trabajo previo.

## Cómo continuar

1. Invocar `dev-flow` y `dev-flow-lessons`. Usar `tui-design` cuando haya UI, `diagnose` para fallos difíciles y `review-packet` al cerrar cada incremento.
2. Reconciliar refs y worktrees antes de escribir:

   ```bash
   git status --short
   git branch -a -vv
   git worktree list
   git log -5 --oneline
   ```

3. Reanudar la fase real que registre cada incremento; no reiniciar E1–E5 ni regenerar evidencia ya válida.
4. Mantener la aprobación general del operador: entregar el review packet y continuar con el siguiente incremento. Solo detener la batería ante una decisión que sea realmente del operador, una compuerta roja o un riesgo externo no autorizado.
5. Después de Inc 6: ejecutar la suite completa en chunks secuenciales, integrar y hacer push a `main` sin esperar su resultado según la enmienda superior, y continuar los incrementos restantes. Plegar requisitos al canon, comprobar trazabilidad y registrar el estado real de G3; los findings de la batería completa pasan al siguiente batch.
6. Si el contexto crece, cerrar el incremento en curso y escribir otro handoff. No compactar a mitad de un incremento.

## Controles que no deben perderse

- Pytest y probes en Linux; Windows solo `py_compile`, extractor y capturas reales de Windows Terminal.
- Transcripts con `python -I -B`, ruta del paquete impresa, HOME/XDG/LOCALAPPDATA aislados, stdin cerrado y `PYTHONDONTWRITEBYTECODE=1`.
- Evidencia como bytes (`-text`), en su hogar permanente y comprometida. No escribir cuentas, hosts, IP ni rutas personales nuevas en evidencia; usar `<user>`, `<runner>`, `<runner-ip>`.
- Mutantes únicamente en copias del árbol. Ningún mutante en el worktree real.
- Snapshots solo mediante CI canónico; no regenerarlos localmente.
- No clipboard ni material A2L propietario.
- No llamar *flaky* a un fallo sin las 10 repeticiones y la tasa exigidas por C-66.
- No hacer push de ramas adicionales sin autorización. El push a `main` después de Inc 6 sí está autorizado por la enmienda superior, sin esperar la batería completa; G3 debe reflejar ese estado pendiente, no un PASS ficticio.

## Prompt para la nueva sesión

```text
Continúa desde `.dev-flow/2026-11-05-batch-103/HANDOFF-2026-11-09-KIMI-BATCH-TO-MAIN.md` en la raíz del repositorio.

Sigue con el incremento, la batería ba hasta que todos los incrementos estén en el main
```
