# Code-Wire coherence check

| Rule | Open |
|---|---|
| C2 · input with no edge | 0 |
| C2 · info: input with a default value and no edge | 5 |
| C2 · input that only a node-to-node call edge (no ports) reaches: open under §3.3 | 0 |
| C3 · output that nothing uses | 0 |
| C4 · node that no source reaches | 0 |
| C4 · node that reaches no sink | 0 |
| C7 · name used two times | 0 |
| C10 · `modify:` target that is not declared | 0 |
| C10 · entity that no node reads or writes | 0 |

## C2 · info: input with a default value and no edge

- `copy_into_workarea.max_size_bytes`
- `before_after_card_text.per_row`
- `before_after_card_text.lead`
- `before_after_card_text.trail`
- `before_after_card_text.row_cap`
