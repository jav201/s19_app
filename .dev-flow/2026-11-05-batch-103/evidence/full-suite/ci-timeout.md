# Ajuste de timeouts de CI — Batch 103

## Origen

- Run: [44198600705](https://github.com/jav201/s19_app/actions/runs/44198600705), evento `push` en `main`.
- HEAD: `3b21c2aa42c2651e81a8eb9fe3fc8af8d7a3a3c7` (`3b21c2aa`).
- Job `tui-ci`: [134446497793](https://github.com/jav201/s19_app/actions/runs/44198600705/job/134446497793).
- El job `snapshot` terminó en verde; WinCI también está verde. Esas señales no sustituyen una ejecución completa de la suite.

## Timeouts medidos

La suite completa comenzó a las `2026-11-17T23:21:28Z`, alcanzó 92 % y fue cortada a las `2026-11-18T02:21:40Z`, tras 180 minutos:

```text
2026-11-18T02:21:39.3561819Z [gw1] [ 92%] PASSED tests/test_tui_patch_editor_v2.py::test_at064a_refresh_rereads_edited_file_into_editor
2026-11-18T02:21:40.6957225Z ##[error]The action 'Run full test suite (pushes)' has timed out after 180 minutes.
```

La fase serial comenzó inmediatamente después y fue cortada a las `2026-11-18T03:06:53Z`, tras 45 minutos:

```text
2026-11-18T03:06:53.2086115Z ##[error]The action 'Run timing arms (pushes)' has timed out after 45 minutes.
```

## Nuevos límites

| Ámbito | Antes | Después |
| --- | ---: | ---: |
| Job `tui-ci` | 240 min | 480 min |
| Paso `Run full test suite (pushes)` | 180 min | 360 min |
| Paso `Run timing arms (pushes)` | 45 min | 90 min |

Se duplican los dos límites agotados para permitir que ambas fases terminen. El límite del job pasa a 480 minutos porque debe contener hasta 450 minutos de los dos pasos, más preparación y sobrecarga del runner. No cambian comandos, workers, tests ni actions.

## Veredicto

Los timeouts impiden obtener un resultado completo de producto en este run. Este cambio sólo amplía el tiempo disponible para repetir la ejecución; **G3 no pasa a GREEN por este cambio** y sigue pendiente del resultado completo de CI.
