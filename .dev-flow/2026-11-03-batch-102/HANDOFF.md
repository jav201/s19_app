# Handoff e ítems abiertos — batch-102 (cierre 2026-11-04)

**Estado:** E5 cerrado. Los 7 incrementos + cierre de validación están en `main`
(merge --no-ff de `batch-102-hotfixes`, commit de merge posterior a `3428439`).
Los dos rulings que quedaban "pending operator ratification" quedan
**ratificados por instrucción explícita del operador** ("Deja un handoff o
reporte de items abiertos. Haz push y merge", 2026-11-04).

## Verificación final (dónde quedó la evidencia)

- Suite completa local: `pytest tests -q -n 8` → 72F / 5331P / 12S / 4X
  (log completo en la sesión, tarea `bash-b5455pfs`).
- Clasificación y fixes: `.dev-flow/2026-11-03-batch-102/04-validation.md`.
- Packet para el operador: `REVIEW-PACKET.md`; rulings:
  `design/E5-review-rulings.md`.

## Ítems abiertos (backlog, por prioridad)

1. **Batch de entorno — snapshots y color:** 23 snapshots de densidad y ~25
   aserciones de color fallan en la PC de trabajo por exportación SVG con el
   tema neutro (no la paleta Calm Dark); se reproducen en el commit base
   `2f2f932`, o sea que NO son regresiones. Re-fijar las baselines o arreglar
   el tema de exportación en un host sano. Hasta entonces la suite completa
   no quedará verde en esta máquina.
2. **Enmienda de requisitos:** LLR-173.6l dice "allows 0 new ones" pero el
   congelado de imports de `screens.py` (TC-B100-64) se movió al head del
   batch-102 por ruling. Actualizar la redacción en `01-requirements.md` para
   que la guarda vuelva a ser un tripwire coherente.
3. **Perf bounds:** `test_tc_b100_20` / `test_tc_b100_61` (<1 s) se midieron
   en un host más rápido; en esta PC pasan/fallan por margen. Considerar
   re-medir con `timing_bound` en el host de referencia o aflojar el bound.
4. **Palette freeze (AT-B78-03):** el congelado Inc-0 nunca se enmendó por
   `a2l_describe_tag` (batch-96) y `confirm_attention` (batch-97); toca
   decidir si se añaden al artefacto congelado o se regenera con disciplina.
5. **Hardening menor:** `powershell.exe` por PATH (ruta absoluta System32),
   aviso de truncado 64 KiB del modal bulk, integración `trace_check.py` con
   los ids `R-B102-*` (diferida a un batch de canon).
6. **TOCTOU source-side** residual en `import_external_ref` — aceptado,
   documentado en `design/E5-review-rulings.md`.

## Notas para la siguiente sesión

- `prototypes/load_projects/` sigue sin trackear en el worktree (preexistente;
  causa la colisión de colección si corres `pytest` sin ámbito `tests/`).
- El marcador `serial_timing` no existe en la suite; no planear una "fase
  serial" futura con ese nombre.
- Los laboratorios (linux-runner / laptop) quedaron apagados; la suite corrió
  en la PC de trabajo con `-n 8` y `pytest-xdist==3.8.0`.
