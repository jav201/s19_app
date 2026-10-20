# Code-Wire annex to the batch-97 PDR

> Method: Code-Wire draft v2.5 (`C:\Users\jjgh8\Github\code-wire` at `6d91188`), forward direction (PDR to DDR).
> Product: `s19_app` at `7d823a7`, Python 3.11.15 (`s19env`), Textual 8.2.8. The product tree was not changed. Marks and the probe ran in a throwaway worktree.
> This annex is an input to the PDR record. It is not a PDR verdict.

## 1. Result first

The method found 4 problems that change a design decision or a test, and that the four PDR reviews did not find. Two of them have executed evidence.

1. **H-X1 (major, executed).** A lane can wait again at a second external step. After the confirmation it loses that wait and its Confirm. The LLR-147.13 two-step arm cannot pass. I-7 and Inc-6 do not list the function.
2. **H-N1/H-N2 (major, recorded).** The NUL refusal codes of LLR-146.14 contradict the shipped codes. The same loaders give other codes for every other unsafe ref. I-6 does not say where the check goes, and one of the two placements keeps TC-B97-62 RED.
3. **H-P1 (major, test design).** The Save arm of TC-B97-06 cannot go RED under its named mutation. Every Patch action ends with a refresh, so the arm is vacuous for the D4 second trigger.
4. **H-W2 (major, extends QA Q-2).** D21 says `_apply_layout` sets widths only. The strip byte count and the clipped card text are painted text, and nothing repaints them on resize.

Seven smaller findings follow in §6. About half of the effort went into format, language and coherence work that found nothing. Most of the value came from the literal threads and the recordings (C16). It did not come from the graph shape. §8 gives the assessment and §9 gives the feedback for the method.

## 2. Scope

`graph-batch97-overview.md` lists the five flows and the reasons. The graph has 57 nodes: 14 NEW, 27 CHANGED and 16 SHIPPED. It traces 22 LLRs of the 65. The other 43 LLRs are layout, colour, help text or test infrastructure, and they have no function contract.

| File | What it holds |
|---|---|
| `graph-patch-json.md` | 17 nodes, D1 to D4 |
| `graph-chip-open.md` | 9 nodes, I-1, D9 |
| `graph-nul-refusal.md` | 10 nodes, I-6 |
| `graph-confirm-key.md` | 9 nodes, D10, D13 to D15, I-7 |
| `graph-width.md` | 12 nodes, D5, D21, D22 |
| `views/` | 12 SVG and 12 PNG views, the generator `gen_views.py`, `status.json` |
| `extract/` | extractor output, marks list, C16 report, recordings, the probe, the C17 and coherence outputs |

## 3. What was done, step by step

1. Read the method (§1 to §8, §10), the canonical text, the language rules and the model graph.
2. Read the design proposal, the six HLRs, the LLRs of the five flows and the code of each node.
3. Recorded the shipped nodes during real tests with `cw_record_plugin.py` (6 test selections and 1 probe).
4. Wrote the five graphs in format B with v2.5 keys.
5. Wrote the marks into the worktree with `codewire_marks.py` and ran `codewire_extract.py`.
6. Declared 6 real calls that the extractor found, and ran it again.
7. Ran `codewire_examples.py` (C16), corrected 9 thread lines, and ran it again.
8. Ran `codewire_ste.py` (C17), applied the §2 scope rule, and shortened 33 sentences.
9. Generated the views from the text.

The recordings are `extract/trace-*.json`. The probe is `extract/probe_two_ext.py`, with its output in `extract/probe-two-ext.txt`.

## 4. Coherence rules C1 to C17

| Rule | Verdict | Evidence and note |
|---|---|---|
| C1 types on edges | ⚠ 1 real mismatch | H-P4: `serialize_change_document` gives `bytes`, `PatchDocumentView.json_text` is `str`. Entity-to-port edges (`[I/O: flow file] ──▶ load_flow_json.flow_path`) join a file to its path, as the pilot did; the types differ by design (M-3) |
| C2 every input fed | ✗ 36 open | `extract/coherence.txt`. 57 inputs have no edge to their port; 21 close with the convention M-3 (a caller computes the value). The 36 left are event payloads from the UI, caller-built arguments and flow-slice edges |
| C3 every output used | ✗ 16 open | `extract/coherence.txt`. 12 are flow-slice edges (the caller is outside the slice); 3 are a `bool` that gates an edge (M-4); 1 is real: `open_folder_in_file_manager.opened` is discarded by the code too |
| C4 reachable and reaching | ✗ 9 + 15 nodes | Event handlers have no source entity; the NUL loaders end at their callers, outside the slice |
| C5 every node traced | ✓ | 57 of 57 nodes have `req:` |
| C6 every functional LLR covered | ✓ in scope | 22 LLRs traced; 43 LLRs out of scope with the reason in §2 |
| C7 unique names | ✓ | 0 duplicates over 57 nodes and 29 entities |
| C8 cycles declared | ✓ | No cycle in the edges. The call-return pair `serialize_change_document` to its caller is written as an edge to the caller output, not as a cycle |
| C9 subsystem balance | n/a | No subsystem has an inner graph of its own. `inner:` lists calls only |
| C10 modify targets and orphans | ✓ | 0 undeclared targets, 0 orphan entities |
| C11 naming rule | ✓ | Rule of this project: node name = code qualname (the extractor binds a mark to the def with that qualname) |
| C12 closed, typed inputs | ✓ after a fix | All defaults written. Writing the NEW layout nodes showed that D21's single `width` input is not closed (H-W1) |
| C13 `Any` has `open:` | ✓ | 4 nodes with `Any` or `Dict[str, Any]`, 4 `open:` lines |
| C14 text = source | ✓ | Every view comes from `gen_views.py` and the text. The overview adds status from `extract/` and says so on the view |
| C15 lifted calls | ⚠ 2 open, waived | 45 lifted calls, 43 declared. 6 real calls were added after the first run. The 2 open ones leave the slice (Save to `scoped_home`, execute-scope to `read_project_manifest`) |
| C16 examples against recordings | ✓ 31 ok, 0 drift | `extract/examples-report.md`. 5 of the 31 ok lines have no anchor, so they pass without a check (M-6). 6 lines not observed, 50 with no recording (NEW behaviour) |
| C17 language | ✓ scoped, ✗ raw | Raw tool: 95 errors over the 5 graphs; the tool reads node blocks as prose (M-2). With the §2 scope rule (`extract/ste_scoped.py`): 0 errors, 8 passive-voice warnings |

The PDR gate of the method asks C1 to C14 and C17 with no violations. C2, C3 and C4 are not met. §9 (M-3, M-4) explains why closing them on a flow slice costs many edges and adds no information.

## 5. Drift against the current code (the forward drift)

The extractor ran over the worktree at `7d823a7` with the marks of the five graphs. Report: `extract/diff-report.md`.

| Kind | Count | Nodes | What the increments must do |
|---|---|---|---|
| Node without code | 14 | `S19TuiApp._patch_document_view`, `json_stamp_text`, `no_project_reason`, `is_openable_chip_dir`, `_FlowExecutionSection.action_confirm_attention`, `FlowExecutionPanel.confirm_attention`, `patch_layout`, `check_layout`, `pipeline_layout`, `lane_layout`, 4 × `_apply_layout` | write them (Inc-1, Inc-3 to Inc-6) |
| Input in the graph, not in the code | 3 | `refresh_entries.document`, `OpenFolderChip.__init__.id_suffix`, `BeforeAfterCard.show_entry.max_bytes` | add the parameters (Inc-4, Inc-1, Inc-4) |
| Parameter not annotated | 2 | `render_run.record`, `apply_confirmed_run.record` | annotate `ChainSetRunRecord` (Inc-6), or accept |
| Type mismatch | 2 | `before` of the card functions | false positive of the extractor (M-5) |
| C15 divergence | 2 | see §4 | waived: outside the slice |
| Behaviour change, same signature | 27 CHANGED nodes, of which 24 have no signature drift | for example `_open_target`, `dict_to_flow`, `_resolve_manifest_entry`, `apply_confirmed_run` | invisible to the extractor; only the `synthetic` example lines show them (M-1) |

## 6. Findings that the reviews did not have

Each finding has its full text in the `## Findings` section of its graph. "Reviews" means `02-review.md` and the PDR conditions UX C1 to C6 and QA Q-1 to Q-6.

| Id | Severity | What | Evidence | Consequence | Changes a decision? |
|---|---|---|---|---|---|
| H-X1 | major | `apply_confirmed_run` sets `paused_block = None` and hides Confirm, also when the re-run waits again | `flow_screens.py:2521`, executed probe (`extract/probe-two-ext.txt`) | the LLR-147.13 two-step arm cannot pass, by key or by button; P-60 measured the record, not the panel | yes: I-7 and the Inc-6 scope |
| H-N1 | major | unsafe read refs give MANIFEST-PATH-ESCAPE in the shipped loaders; LLR-146.14 asks FLOW-UNSAFE-REF and CHAIN-SET-UNSAFE-REF for a NUL | recorded BAT-traversal and TC-B94-31; `tests/test_flow_persistence.py:144-147` | a check placed only in the shared guard keeps TC-B97-62 RED; a pre-reject gives NUL a code that no other unsafe ref gets | yes: I-6 placement, or an LLR amendment |
| H-N2 | minor | unsafe `output_name` has its own code, FLOW-UNSAFE-OUTPUT-NAME | recorded BAT-output-name | same field, two refusal codes | same row as H-N1 |
| H-P1 | major (test) | every Patch action, Save included, ends with `refresh_entries` at `app.py:3265` | recorded TC-B94-10, `app.py:3146-3265` | the Save arm of TC-B97-06 is vacuous for the D4 second trigger; only the typing arm can go RED | yes: TC-B97-06 RED arm, or D1 passes `document=` only on change |
| H-W2 | major | width-dependent painted text (strip bytes, clipped card text, Fields name) is not repainted on resize | `screens_directionb.py:6229-6268`; D21 "sets widths only" | TC-B97-34 and AT-B97-16 can be RED for painted content | yes: D21; extends QA Q-2 (DataTable only) |
| H-P2 | minor | the serialiser runs once for each refresh, not once for each write (11 action kinds, undo, image load, 2 times for one Load) | recorded TC-B94-10: 6 refresh calls, 2 for one Load | §6.2 cost row is wrong; at the S-5 boundary each Validate re-serialises 100,000 entries | yes: D1 or §6.2 |
| H-C1 | minor | without a project the `checks` chip opens `.s19tool/workarea/patches`, but its label is `📂 Open checks/` | recorded TC-703; `folder_open_service.py:217-218` | HLR-148 says the chip opens the folder that its label names | yes: the I-1 label rule |
| H-C2 | minor | nothing reads `_CREATABLE_FAMILIES`; the press path creates for every missing target | `folder_open_service.py:85`, `open_folder_chip.py:160-172` | adding `flows` to it has no effect; `session` refuses with an internal message | yes: I-1 |
| H-C3 | minor (security) | no function produces the family root, the trust anchor of the guard | C2 on `is_openable_chip_dir.root` | `workarea` is the value at hand and refuses the no-project templates chip | yes: one pure node in I-1 |
| H-X2 | minor | the attention state (lane, paint time, confirmed entries) has no named owner | sequence of `[Data: FlowExecutionPanel attention]` | the dwell base can be the record arrival, not the paint | yes: I-7 |
| H-W1 | minor | D21 freezes `<screen>_layout(width)`, but the §3 formulas need card counts and inner widths | C12 on the NEW layout nodes | one `width` input forces Python to repeat the CSS splits | yes: D21 signatures |
| H-P3 | minor | the stamp of the dirty trigger needs a retained count and time, and the view needs a fresh-start value | C2 on `json_stamp_text` | two readings of the stamp time; a fresh start shows the empty line, not `"entries": []` | yes: D2/D4, LLR-148.9 row |
| H-N3 | minor | the NUL checks live in 4 functions that I-6 does not name; 2 EXT-STEP fields accept a NUL today, they do not raise | `flow_persistence_service.py:819-849` | the LLR-146.14 negative control does not describe those 2 arms | no: I-6 text and the NC |
| H-X3 | minor | the re-run log line shows the monotonic clock and "done" for a paused lane | probe run log, `flow_screens.py:2528-2536` | a wrong stamp and a wrong word in the run log | no: Inc-6 scope |
| H-P4, H-W3 | trivial | `bytes` to `str` decode; `show_entry` signature change | see the graphs | small Inc-4 items | no |

## 7. What the graph confirmed or repeated

- **A-1 (writer coverage).** The graph shows that the four `refresh_entries` sites of D1 reach all 8 writers that have an app caller. This confirms the D1 fix; it adds nothing new.
- **QA Q-2.** H-W2 is the same mechanism for painted text.
- **S-1, S2-1 (chip guard).** The graph restates LLR-148.8; H-C3 is the only new part.
- **Q-13, P-36, P-50 (NUL crash).** Known. H-N1 to H-N3 are new.
- **S-5 (100,000 entries).** Known. H-P2 adds the call frequency.
- **UX C1 to C6, QA Q-1, Q-3 to Q-6.** The graph says nothing about them. They are layout, colour, counts, snapshots and the test registry, and Code-Wire has no node for them.

## 8. Value assessment

| Item | Value |
|---|---|
| Effort | about 3 hours of agent time (an estimate; no timer ran) |
| Where the time went | reading and node cut 25 %, recordings and probe 15 %, writing the graphs 25 %, C15/C16/C17 loops 20 %, views 15 % |
| New and decision-changing | H-X1, H-N1/N2, H-P1, H-W2 (major); H-C1, H-C2, H-C3, H-X2, H-W1, H-P2, H-P3 (minor) |
| Where the new findings came from | writing a literal thread for each node (H-X1, H-C1, H-N1, H-N2, H-P1, H-P2), C2 and C12 on NEW nodes (H-C3, H-P3, H-X2, H-W1), `sequence:` (H-W2, H-P3), the extractor C15 run (6 undeclared calls, no finding) |
| Repeated from the reviews | A-1, Q-2, S-1, Q-13, S-5 |
| Cost with no return | C2/C3/C4 closure work, the C17 rewrite of 33 sentences, the view layout |

For this batch the method paid for itself. H-X1 alone would have failed at the Inc-6 gate, after the panel was rebuilt. But the value did not come from the graph as a diagram. It came from the obligation to write one literal thread through each node, and from the recorder that checks the thread. A thread-first variant would have found about 80 % of these findings at about 40 % of the effort.

Such a variant chooses the risky flows and writes examples only for the CHANGED and NEW nodes. Then it records them and probes the arms that have no recording. The layout majority of the batch (UX C1 to C6) is outside the reach of the method.

## 9. Feedback for the method

| Id | Observation | Proposal |
|---|---|---|
| M-1 | NEW, CHANGED and SHIPPED are not fields, and the economy rule is correct. But 24 CHANGED nodes keep their signature, so the extractor cannot see the change. Also, `synthetic` means "no run", not "changed". | Give the markers a rule: `synthetic` = behaviour that the design adds; `inferred` = shipped behaviour with no recording. Then the status derives from text plus marks. This annex used that rule. |
| M-2 | `codewire_ste.py` reads node blocks as prose. The model graph `examples/logtool-graph.md` fails with 3 errors. | Implement the §2 scope rule in the tool. `extract/ste_scoped.py` is a 40-line version: it checks `func`, `desc`, `what`, `consequence` and `decision` only. |
| M-3 | No syntax exists for a value that a caller computes in its body (`external` is named in C2 but not defined). 57 inputs had no producer. | Define it, for example an edge from a node with no port. This annex used that convention. |
| M-4 | A `bool` output that gates an edge (`when:`) has no edge, so C3 reports it. A flow slice has callers outside it, so C3 and C4 report the boundary. | A `## Boundary` section with the outside callers and sinks, and `when:` that can name an output (`when: is_openable_chip_dir.openable`). |
| M-5 | The extractor does not convert `X?` inside a generic (`Sequence[int?]?`), so it reports 2 false mismatches. A closure (`run_chain_set._run_one`) and a callable passed as a value hide real calls (2 false C15 absences). | Convert nested `?`. Lift through nested defs that the marked def calls by name. |
| M-6 | C16 reports `ok` for a line with no anchor (5 of 31). Quoted text shorter than 3 characters is ignored (`"ok"`). | A status `no anchor`, and accept short quoted text. |
| M-7 | `cw_record_plugin.py` stops when a graph node has no def. A forward graph always has such nodes. | Skip a node with no def and list it. This annex wrote recording-only graph files instead. |
| M-8 | In a Textual app, a message (`post_message`) is not a call, so C15 cannot see the panel-to-app links. | Treat a message class as an edge kind, or accept them as declared edges with no lift. |
| M-9 | The PDR gate (C1 to C14 and C17 with no violations) is costly on a slice, and the coherence rules found no design problem here. The threads and the recordings found all the major problems. | At PDR, make C16 threads and C12 on NEW nodes the core of the gate. Keep C2 to C4 as DDR checks over the full map. |

## 10. How the DDR uses this annex

1. At each increment, write the marks into a throwaway worktree with `codewire_marks.py` and run the extractor with the five graphs.
2. Close the 14 nodes without code and the 3 input drifts. Each remaining difference is a graph change with its reason, or a code fix.
3. Replace each `synthetic` line with a thread from the new `test_b97_*` tests, and run C16 with those recordings.
4. Close each `H-*` finding: a code change, a graph change with its reason, or a recorded design decision.
5. Re-run the probe of H-X1 at Inc-6. It must show the second wait and its Confirm.

## Files

All files are in `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-19-batch-97\design\codewire\`.

| Path | Content |
|---|---|
| `graph-*.md` | the five graphs and the overview index |
| `views/*.svg`, `views/*.png` | the views; `views/gen_views.py` generates them; `views/status.json` |
| `extract/diff-report.md`, `extract/extract.json`, `extract/marks.json` | extractor output |
| `extract/examples-report.md`, `extract/trace-*.json` | C16 report and recordings |
| `extract/probe_two_ext.py`, `extract/probe-two-ext.txt` | the H-X1 probe and its output |
| `extract/ste-graphs.txt`, `extract/ste_scoped.py` | C17 output and the scoped checker |
| `extract/coherence.txt`, `extract/coherence_check.py` | C2 to C10 mechanical output |
