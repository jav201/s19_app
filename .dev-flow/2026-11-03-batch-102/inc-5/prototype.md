# Prototipo TUI — Inc 5 — Pestaña A2L en Patch Editor

## Inspector con cuarta pestaña

```text
┌ PATCH ENTRY ────────────────────────────────────────────────┐
│ [Inspector] [JSON] [Checks] [A2L]                           │
├─────────────────────────────────────────────────────────────┤
│ Filter [torque                 ]                            │
│ ┌────┬──────────────────────┬──────────┬────────┐           │
│ │    │ Parameter            │ Address  │ Fmt    │           │
│ │    │ TorqueMax            │ 0x800120 │ u16 Nm │           │
│ │    │ TorqueLimit          │ 0x800122 │ u16 Nm │           │
│ └────┴──────────────────────┴──────────┴────────┘           │
│ 0x800120  u16 Nm  TorqueMax                                 │
│ 200 of 10000 shown — refine filter.                         │
│ [‹ Prev] Page 1/50 [Next ›]                  [Use parameter]│
└─────────────────────────────────────────────────────────────┘
```

## Decisiones

- Se añade una pestaña, no una nueva región permanente: mantiene el PATCH SCRIPT como héroe de la pantalla.
- `Use parameter` transfiere Address/Bytes al formulario Inspector; no muta el documento hasta que el operador use Add/Edit.
- El vocabulario visual es el del picker compartido; solo cambian el prefijo de ids y la acción contextual.
