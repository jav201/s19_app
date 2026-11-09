## Verdict: FAIL — one remaining MAJOR blocker

Static re-review at `a0cff5a4`; no edits or tests performed.

The original seven findings are corrected: backslash-LF lexing (`s19_app/tui/a2l.py:377`), typedef refusal gates (`s19_app/tui/a2l.py:3855-3892`), layout-first datatype precedence (`s19_app/tui/a2l.py:582-593`), family disagreement checks (`s19_app/tui/a2l.py:3709-3761`), preserved diagnostic line (`s19_app/tui/a2l.py:3817-3822`), per-word BYTE_ORDER diagnostics (`s19_app/tui/a2l.py:3651-3655`), and READ.70 closure handling (`s19_app/tui/a2l.py:3905-3937`). Both D8 CUBOID entries statically resolve to **36 bytes** through the same full-span path.

- **MAJOR — impl — scalar inference can still preempt a known full CURVE/MAP-family span.**  
  `s19_app/tui/a2l.py:3726-3750` performs generic `_infer_length_characteristic` before assigning `span`; the fallback at `s19_app/tui/a2l.py:2015-2035` returns a deposit-name element size. For a CURVE on declared layout `UWORD` with two axis points, the layout span is 4 bytes, but `sizeof_from_deposit("UWORD")` produces length 2, preventing the inline span from being assigned. CUBOID/CUBE variants have the same defect.  
  **Requirements:** CTX *sizes*, R-A2L-READ.48 and D8’s full-record-layout-span rule.  
  **Minimal correction:** for `_CURVE_MAP_FAMILY`, select the resolved full span first; when no span resolves, accept only a standing DATA_SIZE/LENGTH rather than generic scalar element-size inference. Keep existing final-refusal guards intact.