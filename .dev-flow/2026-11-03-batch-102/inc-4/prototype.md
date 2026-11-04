# Prototipo TUI — Inc 4 — Add list modal

## Marco propuesto (modal sobre Check Editor)

```text
┌ ADD A2L PARAMETERS ─────────────────────────────────────────┐
│ Separate names with new lines, commas, semicolons or        │
│ spaces.                                                     │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ EngineSpeed_Raw                                         │ │
│ │ VehicleSpeed                                            │ │
│ │ TorqueLimit, TorqueMax                                  │ │
│ └─────────────────────────────────────────────────────────┘ │
│ Included 2 · already included 1 · not found 2 — first       │
│ missing: MissingParam                                       │
│ [Include matches]                              [Close]      │
└─────────────────────────────────────────────────────────────┘
```

## Decisiones de diseño

- El área multilínea es la figura; acciones y resumen quedan en una fila inferior.
- El resumen es de una sola región y con orden fijo: incluidos → ya incluidos → no encontrados.
- El modal no cierra automáticamente tras aplicar: permite corregir nombres no encontrados.
- `esc` cancela; `Include matches` aplica; no hay confirmación por `Enter` para evitar aplicar listas pegadas accidentalmente.
