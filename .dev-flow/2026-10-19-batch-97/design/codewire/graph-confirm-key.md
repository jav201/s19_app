# Code-Wire graph: a waiting lane confirmed by key or by button, then re-run (batch-97, PDR)

> Format B, Code-Wire draft v2.5, forward direction (PDR baseline). The node name is the code qualname (C11 rule of this project).
> Design source: `design/design-proposal.md` D10, D13, D14, D15, I-7. Requirements: HLR-147, LLR-147.3, LLR-147.10, LLR-147.13, LLR-148.9.
> Threads, recorded at `7d823a7`: `TC-1804` (`tests/test_flow_external_step_b96.py::test_tc1804_fx_lane_pause_confirm_rerun`, one external step, `extract/trace-confirm-1804.json`) and `PROBE-2EXT` (a probe of this annex with two external steps, `extract/probe-two-ext.txt` and `extract/trace-confirm-2ext.json`). The key `c`, the dwell and the attention lane do not exist yet, so their lines are `synthetic`.
> Convention: an edge from a node with no port to a port means that the node computes or posts that value in its own body (annex, M-3). A posted Textual message is such an edge.

## Nodes

_FlowExecutionSection.action_confirm_attention
req: LLR-147.13, HLR-147
in: _FlowExecutionSection self
out: None
func: the screen binding of `c`. It hands the key to the panel. A focused Input takes `c` before this binding
module: s19_app/tui/app.py
inner: FlowExecutionPanel.confirm_attention
examples: (AT-B97-20, synthetic) `c` with the focus on a header chip, lane 1 waiting for 0.6 s → the panel confirms lane 1

FlowExecutionPanel.confirm_attention
req: LLR-147.13, LLR-147.3
in: FlowExecutionPanel self
out: None
func: confirms the current waiting entry of the attention lane, as its Confirm button does. The entry must be new and must hold the attention for `CONFIRM_DWELL_S`. Otherwise it confirms nothing and says why on the status line
module: s19_app/tui/flow_screens.py
modify: [Data: FlowExecutionPanel attention] (append); [Interface: status line] (replace)
examples: (TC-B97-64, synthetic) `press("c", "c")`, two lanes waiting, 0.049 s apart → 1 confirm (lane 0); lane 1 still waiting
examples: (TC-B97-64, synthetic) `c` 0.2 s after the attention paint → 0 confirms; status "c ignored: the waiting lane just appeared — press c again"

FlowExecutionPanel.on_button_pressed
req: LLR-147.4, LLR-147.10, LLR-147.13
in: Button.Pressed event
out: None
func: Run disables itself and posts the run request with the mode of the toggle. Confirm of a waiting lane posts the external-step confirmation
module: s19_app/tui/flow_screens.py
modify: [Interface: Run button] (replace)
examples: (TC-1804, inferred) press `#fx_run` → run request {lanes 1 "ext", mode "sequential"}; press `#fx_confirm_0` → confirmation {lane_index 0, block_index 1}
examples: (TC-B97-55, synthetic) 3 presses of Run during one run → 1 run request; `#fx_run` disabled until the record is painted

S19TuiApp.on_flow_execution_panel_run_requested
req: LLR-147.10, LLR-148.9, HLR-147
in: FlowExecutionPanel.RunRequested event
out: None
func: turns the lane payloads into chain specs and runs the set. Any exception becomes one English line in the run log (D14)
module: s19_app/tui/app.py
inner: run_chain_set, FlowExecutionPanel.render_run, FlowExecutionPanel.render_run_error
examples: (TC-1804) event {lanes 1 {name "ext", bindings (0, "base.s19")}, mode "sequential", set_name "chain-set"} → None; the record goes to render_run
examples: (TC-B97-55, synthetic) `run_chain_set` raises → `render_run_error` paints 1 English line; Run enabled again

S19TuiApp.on_flow_execution_panel_external_step_confirmed
req: LLR-147.13
in: FlowExecutionPanel.ExternalStepConfirmed event
out: None
func: builds the confirmation from the declared log and output of the block and re-runs only that lane, then hands the record to the panel
module: s19_app/tui/app.py
inner: run_chain_set, FlowExecutionPanel.apply_confirmed_run, FlowExecutionPanel.render_run_error
examples: (PROBE-2EXT) event {lane_index 0, block_index 1} → None; the re-run record of lane 0 waits again, at block 2

run_chain_set
req: LLR-147.10, LLR-147.13
in: Sequence[ChainSpec] chains; FlowContext ctx; str mode = CHAIN_RUN_SEQUENTIAL; str set_name = "chain-set"; (Callable) (Flow, FlowContext->FlowRunResult)? run_one = None; (Callable) (->float)? clock = None
out: ChainSetRunRecord record {mode, outcomes, report_path}
func: runs each chain of the set, sequential or parallel, and keeps one outcome for each chain
module: s19_app/tui/services/flow_execution_service.py
inner: run_flow, _chain_inputs
examples: (TC-1804) chains 1 {name "ext"}; mode "sequential" → record {outcomes 1 {status "paused", block 1 "waiting"}}
examples: (PROBE-2EXT) re-run with block 1 confirmed → record {outcomes 1 {status "paused", block 2 "waiting", block 3 "skipped"}}

FlowExecutionPanel.render_run
req: LLR-147.3, LLR-147.10, LLR-147.13
in: ChainSetRunRecord record
out: None
func: paints lanes and run log from the record. Marks each waiting lane. Names the first painted waiting lane as the attention lane and starts its dwell after the paint. Scrolls it into view. Enables Run again
module: s19_app/tui/flow_screens.py
modify: [Data: FlowExecutionPanel lanes] (replace); [Data: FlowExecutionPanel attention] (replace); [Interface: lanes] (replace); [Interface: run log] (replace); [Interface: Run button] (replace)
examples: (TC-1804) record {outcomes 1 {status "paused", block 1 "waiting"}} → None; lane 0 paused at block 1; Confirm of lane 0 shown
examples: (AT-B97-20, synthetic) two lanes waiting → attention lane 0; REQUIRED line "log + output file: REQUIRED for ext · press c to confirm"

FlowExecutionPanel.apply_confirmed_run
req: LLR-147.13
in: int lane_index; ChainSetRunRecord record
out: None
func: paints the re-run of one lane after a confirmation. A re-run that waits again keeps the lane waiting and moves the attention to its next entry
module: s19_app/tui/flow_screens.py
modify: [Data: FlowExecutionPanel lanes] (replace); [Data: FlowExecutionPanel attention] (replace); [Interface: lanes] (replace); [Interface: run log] (append)
examples: (TC-1804) lane_index 0; record {outcomes 1 {status "ok"}} → None; Confirm of lane 0 hidden
examples: (PROBE-2EXT) lane_index 0; record {outcomes 1 {status "paused", block 2 "waiting"}} → None; on main the lane keeps status paused but paused_block None and Confirm of lane 0 hidden; the run log line reads □ ext2 · done, with a monotonic stamp (probe output, H-X3)
examples: (TC-B97-64, synthetic) the same record → lane 0 waiting at block 2; Confirm shown; one more `c` after the dwell confirms it

FlowExecutionPanel.render_run_error
req: LLR-147.10, LLR-148.9
in: str message
out: None
func: paints one English refusal or error line in the run log and enables Run again
module: s19_app/tui/flow_screens.py
modify: [Interface: run log] (replace); [Interface: Run button] (replace)
examples: (TC-B97-55, synthetic) message "run failed: ValueError" → run log 1 line; `#fx_run` enabled

## Entities

[Data: FlowExecutionPanel lanes]
in: list[_FxLane]
desc: the lanes of the set with their last status, `fail_block` and `paused_block` (`flow_screens.py:1841`)

[Data: FlowExecutionPanel attention]
in: tuple
desc: the attention lane index, its waiting block, the monotonic time of its paint and the confirmed entries. No design element names this state yet (see H-X2)
sequence:
  runPauses: render_run wins → (paint) → confirm_attention
  confirmByKey: confirm_attention → on_flow_execution_panel_external_step_confirmed → run_chain_set → apply_confirmed_run wins
  secondWait: apply_confirmed_run wins → (paint) → confirm_attention
  strayEnter: on_button_pressed → on_flow_execution_panel_run_requested → run_chain_set → render_run wins

[I/O: monotonic clock]
in: float
desc: `time.monotonic()`, the dwell base (design §6.2)

[Data: S19TuiApp active project]
in: Path?
desc: the project directory. A run with no project paints the refusal line

[Interface: lanes]
in: str
desc: the lane rows, cards, cables and `#fx_confirm_<i>`

[Interface: run log]
in: str
desc: `#fx_log`

[Interface: Run button]
in: bool
desc: the disabled flag of `#fx_run` (D14)

[Interface: status line]
in: str
desc: the app status line

## Edges

[Data: FlowExecutionPanel attention] ──▶ FlowExecutionPanel.confirm_attention
[Data: FlowExecutionPanel lanes] ──▶ FlowExecutionPanel.confirm_attention
[I/O: monotonic clock] ──▶ FlowExecutionPanel.confirm_attention
[I/O: monotonic clock] ──▶ FlowExecutionPanel.render_run
[Data: FlowExecutionPanel lanes] ──▶ FlowExecutionPanel.on_button_pressed
[Data: FlowExecutionPanel lanes] ──▶ S19TuiApp.on_flow_execution_panel_external_step_confirmed
[Data: S19TuiApp active project] ──▶ S19TuiApp.on_flow_execution_panel_run_requested
[Data: S19TuiApp active project] ──▶ S19TuiApp.on_flow_execution_panel_external_step_confirmed
FlowExecutionPanel.confirm_attention ──▶ S19TuiApp.on_flow_execution_panel_external_step_confirmed.event
FlowExecutionPanel.on_button_pressed ──▶ S19TuiApp.on_flow_execution_panel_external_step_confirmed.event
when: the pressed button is `#fx_confirm_<i>` of a waiting lane
FlowExecutionPanel.on_button_pressed ──▶ S19TuiApp.on_flow_execution_panel_run_requested.event
when: the pressed button is `#fx_run`
S19TuiApp.on_flow_execution_panel_run_requested ──▶ run_chain_set.chains
S19TuiApp.on_flow_execution_panel_external_step_confirmed ──▶ run_chain_set.chains
run_chain_set.record ──▶ FlowExecutionPanel.render_run.record
when: the run was a set run
run_chain_set.record ──▶ FlowExecutionPanel.apply_confirmed_run.record
when: the run was a confirmation re-run
S19TuiApp.on_flow_execution_panel_run_requested ──▶ FlowExecutionPanel.render_run_error.message
when: no project, or `run_chain_set` raised

## Findings

H-X1
anchor: FlowExecutionPanel.apply_confirmed_run
what: after a confirmation the re-run can wait again at a second external step, but `apply_confirmed_run` always sets `paused_block = None` and hides Confirm. The lane shows no wait and offers no Confirm
evidence: `flow_screens.py:2517-2526`; executed PROBE-2EXT (`extract/probe-two-ext.txt`): first run `(paused_block 1, Confirm shown)`, after confirm `(None, hidden, status 'paused')`; P-60 measured the service record only
consequence: the LLR-147.13 arm "press c again after the pause confirms the next entry" (flash2_chain) cannot pass: no waiting lane remains, by key or by button. I-7 and §6.1 do not list `apply_confirmed_run` as changed
decision: changes I-7 / Inc-6 scope: `apply_confirmed_run` derives `paused_block` from the waiting result, as `render_run` does (`flow_screens.py:2429-2445`), and re-arms the attention

H-X2
anchor: [Data: FlowExecutionPanel attention]
what: the attention lane, the paint time of its wait and the set of confirmed entries are state that `confirm_attention` reads. No decision names this state, its writers or the post-paint hook that sets the dwell base
evidence: D10, D15, §6.2 row "the dwell is measured from the attention paint's `time.monotonic()`"; §1.3 "attention lane … once that lane has been painted"
consequence: two writers (`render_run`, `apply_confirmed_run`) and one reader with an order rule (paint first). Without a named owner, the dwell can start at the record arrival. The 0.049 s burst arm (P-60) does not separate that time from the paint
decision: adds to I-7: the attention state, its two writers and the `call_after_refresh` hook that stamps the dwell base

H-X3
anchor: FlowExecutionPanel.apply_confirmed_run
what: the re-run lines of the run log use the absolute monotonic time and the status glyph without its word: "29535:44.249 □ ext2 · done"
evidence: `flow_screens.py:2528-2536` (`_fx_stamp(outcome.started_at)` with no run start subtracted, and " · done" for every status); PROBE-2EXT run log
consequence: the run log of a confirmed lane shows a clock value and calls a paused lane "done". LLR-147.5 rewrites these strings in English but no LLR reads the stamp or the paused wording
decision: no D change. Record it in the Inc-6 scope beside H-X1 (same function)
