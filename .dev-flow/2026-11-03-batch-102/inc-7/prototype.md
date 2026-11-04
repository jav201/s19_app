# Prototipo TUI — Inc 7 — Origen y selector de archivos

## Tarjeta con origen

```text
┌ PATCH ─────────────┐
│ calib_hotfix.json  │
│ ↳ project          │
└─────────┬──────────┘
```

Estados: `project`, `temp`, `loaded`, `external`, `missing`.

## Selector Browse

```text
┌ CHOOSE INPUT FILE ──────────────────────────────────────────┐
│ Project                                                     │
│   firmware.s19            calib_hotfix.json                 │
│ Temp / workarea                                             │
│   baseline.hex            trial.a2l                         │
│ Loaded artifacts                                            │
│   current image (firmware.s19)                              │
│ External path                                               │
│ [C:\tmp\external.json                    ] [Import]         │
│                                                             │
│                                      [Cancel]               │
└─────────────────────────────────────────────────────────────┘
```

## Decisiones visuales

- La anotación `↳ source` es dim; `missing` usa el color semántico de alerta.
- Browse rellena el campo activo; el bloque sólo cambia con Add/Save.
- El import externo informa `imported as external/calib.json` en la misma fila.
