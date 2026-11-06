# Inc 5 — E4 implementation notes (unit B: Check Editor + guide text)

Unit B of batch-101 Inc 5, design-first flow. Files: `s19_app/tui/screens_directionb.py`,
`docs/user-guide/ch10-check-editor.md`. Graph nodes owned (per
`codewire/graph-inc5.md` group G3): `CheckEditorPanel.__init__` (#8),
`CheckEditorPanel.set_a2l_parameters` (#9), `CheckEditorPanel.load_spec` (#10),
`CheckEditorPanel._named_parameter` (#11), `CheckEditorPanel._collected_items` (#12),
`CheckEditorPanel._rebuild_memory_table` (#13), `CheckEditorPanel._add_memory_row` (#14),
`CheckEditorPanel._on_a2l_parameter_picker_selection_changed` (#15),
`CheckEditorPanel._prune_spec_bytes` (#16), `CheckEditorPanel._demote_moved_spec_params` (#17),
plus the E4-addendum guide text (E1-slice §1, E1-rulings §1 (5)-(7), E3 ruling SEC5-3 / A-3).

## Functions changed per file

`s19_app/tui/screens_directionb.py`:

- `CheckEditorPanel.__init__` — changed (#8): `_memory_rows` now holds I-4
  4-tuples `(address, label, size, expected)`; adds
  `self._spec_bytes: dict = {}` (included parameter name → its spec entry
  `(address, size, bytes)` from the last picked spec).
- `CheckEditorPanel.set_a2l_parameters` — changed (#9): captures
  `kept = list(self._picker.picked_params)` before the `set_parameters` no-op
  check; after a real repopulation it demotes moved/resized/dropped spec picks
  (`_demote_moved_spec_params`), re-includes the surviving earlier picks in
  order (`include_names`, which ignores unknown names — R-CHKED-055), prunes
  `_spec_bytes`, rebuilds the memory table only when a demotion appended a row,
  then the base layout reset and preview refresh.
- `CheckEditorPanel.load_spec` — changed (#10): clears picks and `_spec_bytes`;
  builds `by_key` `(address, size) → names` once from `self._param_rows`
  (integer addresses, ledger order); for each entry resolves the named parameter
  via `_named_parameter` (symbol first, then the unique address+size match) and
  includes it in entry order with its spec entry `(address, size, bytes)`;
  entries without one become unlabelled memory rows carrying their spec bytes.
- `CheckEditorPanel._named_parameter` — new (#11): the named-parameter rule —
  a non-empty symbol the ledger lists names the entry only when its range equals
  the entry's address and byte count and it is not taken (no address fallback on
  a range mismatch, E3 A-6); otherwise the single parameter at the entry's
  address and byte count, when exactly one and not taken; else `None`.
- `CheckEditorPanel._collected_items` — changed (#12): each item gains
  `expected` — a parameter's spec bytes only while its current ledger range is
  its spec entry's (else `None`), a memory row's fourth tuple element.
- `CheckEditorPanel._rebuild_memory_table` — changed (#13): unpacks the 4-tuple
  rows (cells unchanged).
- `CheckEditorPanel._add_memory_row` — changed (#14): appends
  `(address, label, size, None)`.
- `CheckEditorPanel._on_a2l_parameter_picker_selection_changed` — changed (#15):
  `self._prune_spec_bytes()` before `self._refresh_preview()`.
- `CheckEditorPanel._prune_spec_bytes` — new (#16): keeps only the `_spec_bytes`
  entries of currently picked names whose ledger range is still their spec
  entry's.
- `CheckEditorPanel._demote_moved_spec_params` — new (#17): for each pre-repop
  pick with a spec entry whose new ledger range no longer matches, appends the
  memory row `(spec[0], default_label, spec[1], spec[2])` in kept order, deletes
  the `_spec_bytes` entry, and leaves the name out of the re-include list;
  returns the rest in kept order. Never reads the image and never changes a spec
  entry's address, size or bytes.

## Guide lines changed

`docs/user-guide/ch10-check-editor.md` (§10.6, §10.7, §10.8 — text only):

- §10.6 *Validate*: adds that a field loaded back from a spec is compared with
  the bytes that spec declared, so Validate can report `fail` when the image no
  longer matches the spec.
- §10.7 *Write the spec*: replaces the stale F-26 text (collector dropping to
  `1 field: 0 params`) with — the collector keeps its fields; Write does not
  re-baseline a spec-loaded field against the image (it writes the spec's bytes
  again); to re-baseline one field, exclude and include the parameter or remove
  and add the memory row; a rewritten spec lists its parameter entries first.
- §10.8 *Load a spec back*: replaces the stale F-27 "parameter names not
  restored" text with — entries whose parameter the A2L lists come back as `✓`
  parameters; the `SERIAL` label is not restored; a parameter a newly loaded A2L
  moves, resizes, or no longer lists comes back as an unlabelled `▪` memory row
  at the spec's address.

## Deviation from the graph

None for the code. All ten G3 nodes are implemented exactly as the graph states
them, including: the demotion appends in `kept` order at the spec entry's own
address/size/bytes and never reads the image; the prune keys on the current
picks (not `event.names`) and drops a still-picked name off its spec entry's
range; `_named_parameter` never falls back to the address rule when a listed
symbol's range differs (E3 A-6).

Guide note (not a code deviation): the F-01 sentence at the end of §10.8
("A spec with `symbol` entries … refused the same way as in the Patch Editor")
was left unchanged in content and only reflowed, because it is outside the
E4-assigned text (`E1-rulings.md` §1 (5)-(7), `E1-slice.md` §1).

## py_compile result

`python -m py_compile s19_app/tui/screens_directionb.py` → OK (exit 0, no
output). CRLF line endings preserved in `screens_directionb.py` and in the guide
(verified by byte scan: every new line added is CRLF-terminated, no lone CR).
