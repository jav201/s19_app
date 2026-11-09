# Handoff de sesión — batch-103 → Inc 12

## Punto de reanudación

El operador **aprobó Inc 3a** y pidió continuar en una sesión nueva. La siguiente unidad es **Inc 12 — A2L tag table: no glued or cut values**.

- Worktree: `C:\Users\<user>\Github\s19_app-b103`
- Rama: `batch-103`
- HEAD al escribir este handoff: `aa88a0c8a236`
- `origin/main`: `235b4c3692c7`; no se ha publicado ningún cambio del batch.
- Árbol limpio al escribir este handoff; no hay procesos ni escritores activos.

## Leer primero, en este orden

1. `.dev-flow/2026-11-05-batch-103/PLAN.md` — alcance, dependencias, G2/G3 y reglas de plataforma.
2. `.dev-flow/2026-11-05-batch-103/inc-12/` — requisitos, grafo, rulings y evidencia ya existentes; no reiniciar E1–E3 si ya están aprobados.
3. `.dev-flow/2026-11-05-batch-103/HANDOFF-2026-11-09-KIMI-INC3A-E4.md` — cierre canónico y notas LOW de Inc 3a.
4. `.dev-flow/2026-11-05-batch-103/inc-3/04-validation.md` y `REVIEW-PACKET.md` — evidencia y paquete aprobado de Inc 3a.
5. `CLAUDE.md` — comandos y law guards del proyecto.

## Estado comprometido que no debe repetirse

- Inc 11 integrado en `aa7f871c`.
- Inc 3a integrado en `3feed9cc9a66`; evidencia de integración en `aa88a0c8a236`.
- Inc 3a: 471 pruebas funcionales, 33 timing, 22 escalar, 103 mutantes eliminados; 275 full + 5 partial; solo 12 gaps TEST pertenecientes a Inc 3b.
- La aprobación de Inc 3a no cierra Inc 12 ni autoriza publicar el batch.

## Primera acción de la nueva sesión

Reanudar el estado real de Inc 12 desde sus artefactos y registrar el inicio en `inc-12/steps.log`. No crear otro grafo ni reabrir decisiones aprobadas salvo un finding que las refute.

Inc 12 exige, antes de cerrar:

- Address y Length como las dos primeras columnas fijas; padding entre celdas.
- Tag limitado con `…` visible según el ancho restante, sin valores pegados ni cortes silenciosos.
- Capturas reales de **Windows Terminal a 80, 118 y 220 columnas**, antes/después, con aprobación explícita del operador.
- Revisión del backlog E3 sobre scroll horizontal y celdas cortadas a la izquierda.

Usar `dev-flow` y `dev-flow-lessons`; para la revisión visual, `tui-design`. Al cerrar, generar `review-packet`. DeepSeek v4 Pro queda para implementación mecánica y drivers, siempre detrás de tester/revisor independiente y con propiedad de archivos disjunta.

## Reglas operativas vigentes

- Pytest y probes en Linux; en Windows solo `py_compile`, `codewire_extract.py` y las capturas reales autorizadas de Inc 12.
- Usar los accesos RTX/laptop ya configurados por el operador, sin escribir cuentas, nombres de host, IP ni rutas personales en evidencia nueva.
- En cada transcript: `python -I -B`, `sys.path.insert(0, checkout)` y `s19_app.__file__` al inicio; HOME/XDG/LOCALAPPDATA aislados bajo `zq_iso_user`, stdin cerrado y `PYTHONDONTWRITEBYTECODE=1`.
- No clipboard, material A2L propietario ni texto del corpus público en registros nuevos.
- Evidencia como bytes (`-text`); comparar staged/worktree antes de commit.
- No mutantes en el worktree real, no escritores paralelos sobre un mismo archivo y no cambios de fuente/alcance durante ejecuciones largas.
- Commits por etapa; no merge/push a `main` hasta cerrar todos los incrementos, suite completa, canon, trazabilidad global y revisión final.

## Después de Inc 12

Seguir el PLAN: **2b/3b, 5, 6**; después **1b/10/7/8/9** según G2. Al final: suite completa en chunks secuenciales, fold al canon, `trace_check` de todo el batch con correcciones/canon y paquete de revisión final.

Inc 1a conserva una incidencia separada de evidencia Windows held-clipboard (run 5: 14 failed, 63 passed, 37 skipped). Necesita diagnóstico o aceptación parcial explícita del operador; no está resuelta por Inc 3a.
