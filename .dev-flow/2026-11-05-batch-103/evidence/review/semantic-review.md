# Pasada de revisión estructurada — g3-review.html · 2026-11-16

**Alcance:** género A (reporte para operador). Reglas aplicadas: R3a, R9, R10, R11, R12 y R13. No aplicada: R3b, cabeza histórica exclusivamente didáctica. Lectura semántica posterior a las comprobaciones mecánicas y al navegador headless; no se emite calificación.

## R3a · Escala de agregación — SIN HALLAZGOS

La cabecera acota el sistema y su bloqueo; la descomposición en incrementos precede a los resultados, riesgos y decisión. Cita de control: «Estado final escrito en cada `04-validation.md`; no es un veredicto agregado de G3.» — `#incrementos`. La agregación no se confunde con un PASS global.

## R9 · Entidades nombradas — SIN HALLAZGOS

Las entidades que sostienen la decisión quedan tipificadas por su función antes de usarse como argumento: la full-suite es una puerta de ejecución, AT-I1b-8 una aceptación manual, P-059 una decisión visual y GC-C14 un mutante no válidamente ejecutado. Citas de control: «AT-I1b-8 · aceptación manual del operador» — `#at-i1b-8`; «Mutante BAD/bloqueado por diseño» — `#riesgos`; «Aprobación visual limitada a P-059 y a estas ocho capturas» — `#capturas`.

## R10 · Bloque según operación mental — SIN HALLAZGOS

La tabla descompone incrementos, la galería permite inspección visual, el checklist secuencia la AT y el formulario ejecuta una decisión local. Cita de control: «Los checkboxes son sólo ayuda local: no cambian el estado `not_run`, no se guardan y no desbloquean G3.» — `#at-i1b-8`. No hay canvas, Mermaid, MathJax ni aparato pedagógico.

## R11 · Relevancia antes que rigor — SIN HALLAZGOS

El bloqueo y sus consecuencias aparecen antes de cifras y detalles. Cita de control: «La trazabilidad final está completa, pero la full-suite y su self-test no se ejecutaron por conectividad SSH. AT-I1b-8 también sigue manual not_run.» — `#resumen`. Cada precisión posterior explica qué evidencia falta o qué no puede inferirse.

## R12 · Jerarquía del sistema — SIN HALLAZGOS

Los componentes de primer orden tienen encabezados propios: «Los 15 incrementos», «Capturas reales Inc 1b», «AT-I1b-8», «Resultados clave y sus límites», «Riesgos y pendientes» y «Decisión de revisión G3» — IDs `#incrementos`, `#capturas`, `#at-i1b-8`, `#resultados`, `#riesgos`, `#decision`. Ninguno queda subordinado a un marco retórico.

## R13 · Consulta sin perder posición — SIN HALLAZGOS

No se añadió un glosario lineal. Fuentes, precondiciones y diagnóstico se consultan mediante `<details>` en el punto de uso; la navegación ancla permanece disponible. Citas de control: «Fuentes primarias del estado G3» — `#resumen`; «Precondiciones literales» — `#at-i1b-8`.

## Resumen

No se encontraron hallazgos semánticos que exigieran otra iteración. Esta pasada ordena hallazgos cuando existen; no puntúa ni cambia el estado G3, que permanece **BLOCKED**.
