"""Exact copy-only mutations and discriminating nodes for Inc 9b M9b."""

from pathlib import Path

B = "s19_app/tui/screens_directionb/patch_editor/bench_sheet.py"
V = "s19_app/tui/definition_bench_view.py"
P = "s19_app/tui/app/patch.py"
W = "tests/test_b103_inc9b_w.py"
S = "tests/test_b103_inc9b_s.py"
AT = "tests/test_b103_inc9b_at.py"


def node(module, name):
    return f"{module}::test_{name}"


def control(control_id, requirement, mutation, nodes):
    return {
        "id": control_id,
        "requirement": requirement,
        "mutation": mutation,
        "nodes": tuple(nodes),
    }


N94A = node(W, "r_pe_bench_94_4_a_queued_decode_shows_its_cue_while_another_rows_summary_runs")
N102_1 = node(W, "r_pe_bench_102_1_leaving_the_row_for_a_scalar_returns_the_idle_look_while_the_worker_runs")
N102_2 = node(W, "r_pe_bench_102_2_a_filter_that_drops_the_row_returns_the_idle_look_within_0_3_s")
N98_AT = node(AT, "r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record")
N99_AT = node(AT, "r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second")
N100_1 = node(W, "r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show")
N100_2 = node(W, "r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result")
N100_3 = node(AT, "r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step")
N101_3 = node(S, "r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look")
N101_4 = node(S, "r_pe_bench_101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look")
N106_2 = node(S, "r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere")

BUSY_JOB_ACTIVE = (
    B,
    "        job = busy_job(name, self.states.get(name), self._busy_stage_name())",
    "        job = None if self._active_job is None else self._active_job[:2]",
)
RECORD_HOLD = (
    P,
    "        finally:\n            if not wrote:\n                sheet.record_done(event.name)",
    "        finally:\n            pass",
)
REFRESH_STALL = (
    P,
    "        def sheet() -> None:\n            self.query_one(\"#patch_editor_panel\", PatchEditorPanel).refresh_sheet_document()",
    "        def sheet() -> None:\n            __import__(\"time\").sleep(1.3)\n            self.query_one(\"#patch_editor_panel\", PatchEditorPanel).refresh_sheet_document()",
)
CHAIN_AFTER_REFRESH = (
    P,
    "                self.set_timer(STEP_GAP_S, lambda: run(index))",
    "                self.call_after_refresh(run, index)",
)

GROUPS = {
    "G01": {
        "controls": [
            control("N-94a", "R-PE-BENCH.94", "bench_sheet.py:526: key the cue to the active running job", [N94A]),
            control("N-102", "R-PE-BENCH.102", "bench_sheet.py:526: key the cue to the active running worker", [N102_1, N102_2]),
        ],
        "edits": [BUSY_JOB_ACTIVE],
    },
    "G02": {
        "controls": [control("N-94b", "R-PE-BENCH.94", "bench_sheet.py:119-120: omit busy-timer creation", [node(AT, "r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second")])],
        "edits": [(B, "    def on_mount(self) -> None:\n        self._busy_timer = self.set_interval(BUSY_TICK_S, self._busy_tick, pause=True)", "    def on_mount(self) -> None:\n        pass")],
    },
    "G03": {
        "controls": [control("N-95a", "R-PE-BENCH.95", "bench_sheet.py:48: reduce busy grace to zero", [node(W, "r_pe_bench_95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue")])],
        "edits": [(B, "BUSY_GRACE_S = 0.2", "BUSY_GRACE_S = 0.0")],
    },
    "G04": {
        "controls": [control("N-95b", "R-PE-BENCH.95", "bench_sheet.py:56,154: count summary jobs as busy at both sites", [node(W, "r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs")])],
        "edits": [
            (B, 'state.job in ("decode", "preview")', 'state.job in ("decode", "preview", "summary")'),
            (B, 'if kind in ("record", "decode", "preview"):', 'if kind in ("record", "decode", "preview", "summary"):'),
        ],
    },
    "G05": {
        "controls": [control("N-96a", "R-PE-BENCH.96", "definition_bench_view.py:538: pad seconds to width four", [node(W, "r_pe_bench_96_1_the_busy_title_reads_spinner_busy_job_name_seconds_and_keys_still_work")])],
        "edits": [(V, 'tail = f" · {seconds:.1f} s · keys still work "', 'tail = f" · {seconds:4.1f} s · keys still work "')],
    },
    "G06": {
        "controls": [control("N-96b", "R-PE-BENCH.96", "definition_bench_view.py:544: remove the busy-pill background", [node(W, "r_pe_bench_96_2_the_pill_is_bold_dark_on_amber_and_the_title_keeps_its_colour")])],
        "edits": [(V, 'style=f"bold {DEPTH_BG} on {BUSY_COLOR}"', 'style=f"bold {DEPTH_BG}"')],
    },
    "G07": {
        "controls": [control("N-97a", "R-PE-BENCH.97", "bench_sheet.py:538-540: paint the busy title only on frame zero", [node(AT, "r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title")])],
        "edits": [(
            B,
            "        win.border_title = busy_title(\n            str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4\n        )",
            "        if self._busy_frame == 0:\n            win.border_title = busy_title(\n                str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4\n            )",
        )],
    },
    "G08": {
        "controls": [control("N-97b", "R-PE-BENCH.97", "bench_sheet.py:192,233: run bench jobs synchronously with direct completion", [node(AT, "r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds")])],
        "edits": [
            (B, '@work(thread=True, group="bench", exit_on_error=False)', '@work(thread=False, group="bench", exit_on_error=False)'),
            (B, "        self.app.call_from_thread(self._job_done, kind, name, generation, result, derived)", "        self._job_done(kind, name, generation, result, derived)"),
        ],
    },
    "G09": {
        "controls": [control("N-98a", "R-PE-BENCH.98", "patch.py:411-413: run the write and full refresh in one UI-thread call", [N98_AT, node(S, "r_pe_bench_98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh")])],
        "edits": [(
            P,
            "        self._run_refresh_steps(\n            self._patch_refresh_steps(), lambda: sheet.record_done(event.name)\n        )",
            "        self._refresh_patch_history_view()\n        sheet.record_done(event.name)",
        )],
    },
    "G10": {
        "controls": [
            control("N-98b", "R-PE-BENCH.98", "patch.py:731-732: add a 1.3-second stall to the sheet refresh step", [N98_AT]),
            control("N-99", "R-PE-BENCH.99", "patch.py:731-732: add a 1.3-second stall to the sheet refresh step", [N99_AT]),
        ],
        "edits": [REFRESH_STALL],
    },
    "G11": {
        "controls": [control("N-100a", "R-PE-BENCH.100", "bench_sheet.py:546-547: leave the inline busy-border rules installed", [N100_1, N100_2, N100_3])],
        "edits": [(B, '        for edge in ("border_top", "border_right", "border_bottom", "border_left"):\n            win.styles.clear_rule(edge)\n', "")],
    },
    "G12": {
        "controls": [control("N-100b", "R-PE-BENCH.100", "bench_sheet.py:548: leave the last busy title in place", [N100_1, N100_2, N100_3])],
        "edits": [(B, "        win.border_title = self._busy_idle_title\n", "")],
    },
    "G13": {
        "controls": [control("N-101a", "R-PE-BENCH.101", "bench_sheet.py:282,310 and patch.py:406-408: preserve busy state on unsuccessful results", [
            node(W, "r_pe_bench_101_1_a_preview_refusal_returns_the_idle_look_within_0_3_s"),
            node(AT, "r_pe_bench_101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s"),
            N101_3,
            N101_4,
            node(AT, "r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s"),
            node(W, "r_pe_bench_101_6_a_decode_whose_worker_raises_returns_the_idle_look_within_0_3_s"),
        ])],
        "edits": [
            (B, "        if result is None:\n            return replace(state, job=None) if state.job == kind else state", "        if result is None:\n            return state"),
            (B, '            job=None if state.job == "preview" else state.job,', '            job=None if state.job == "preview" and not isinstance(result, Refusal) else state.job,'),
            RECORD_HOLD,
        ],
    },
    "G14": {
        "controls": [control("N-101b", "R-PE-BENCH.101", "patch.py:406-408: keep the record hold after a refusal", [N101_3, N101_4])],
        "edits": [RECORD_HOLD],
    },
    "G15": {
        "controls": [control("N-103", "R-PE-BENCH.103", "bench_sheet.py:538-540: assign the busy title as a markup string", [
            node(W, "r_pe_bench_103_1_a_markup_name_is_shown_literally_with_no_link"),
            node(W, "r_pe_bench_103_2_brackets_in_a_name_are_shown_literally"),
        ])],
        "edits": [(
            B,
            "        win.border_title = busy_title(\n            str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4\n        )",
            "        win.border_title = str(busy_title(\n            str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4\n        ))",
        )],
    },
    "G16": {
        "controls": [control("N-104", "R-PE-BENCH.104", "definition_bench_view.py:540: use the raw busy-name string", [
            node(W, "r_pe_bench_104_1_an_escape_sequence_in_a_name_is_painted_as_fffd"),
            node(W, "r_pe_bench_104_2_a_c1_control_in_a_name_is_painted_as_fffd"),
        ])],
        "edits": [(V, "    echo = name_echo(name)", "    echo = name")],
    },
    "G17": {
        "controls": [control("N-105", "R-PE-BENCH.105", "definition_bench_view.py:541-542: omit busy-name truncation", [
            node(W, "r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[80x24]"),
            node(W, "r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[118x54]"),
            node(W, "r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[220x60]"),
        ])],
        "edits": [(V, "    if len(echo) > room_for_name:\n        echo = echo[: room_for_name - 1] + \"…\"\n", "")],
    },
    "G18": {
        "controls": [control("N-106", "R-PE-BENCH.106", "patch.py:755: ignore the document token on later refresh steps", [
            node(S, "r_pe_bench_106_1_an_undo_between_two_refresh_steps_leaves_the_undone_document_everywhere"),
            N106_2,
        ])],
        "edits": [(P, "                    self._patch_document_token() != token\n                    or not self.query(\"#patch_editor_panel\")", "                    False\n                    or not self.query(\"#patch_editor_panel\")")],
    },
    "G19": {
        "controls": [
            control("I-CHAIN-98", "R-PE-BENCH.98", "patch.py:766: replace timer separation with call_after_refresh", [N98_AT]),
            control("I-CHAIN-99", "R-PE-BENCH.99", "patch.py:766: replace timer separation with call_after_refresh", [N99_AT]),
        ],
        "edits": [CHAIN_AFTER_REFRESH],
    },
    "G20": {
        "controls": [control("I-TOKEN-DROP", "R-PE-BENCH.106", "patch.py:779: remove write generation from the document token", [N106_2])],
        "edits": [(P, "            self._image_write_generation,\n", "")],
    },
    "G21": {
        "controls": [control("I-NO-INCREMENT", "R-PE-BENCH.106", "patch.py:1872: stop the in-place-write generation increment", [N106_2])],
        "edits": [(P, "        self._image_write_generation += 1\n", "")],
    },
    "G22": {
        "controls": [control("I-LATER-RAISE", "R-PE-BENCH.98/2", "patch.py:762-764: omit cleanup when a later refresh step raises", [node(S, "r_pe_bench_98_2_a_later_step_raise_releases_record_done_exactly_once")])],
        "edits": [(P, "            except BaseException:\n                on_done()\n                raise\n", "")],
    },
    "G23": {
        "controls": [control("I-PANEL-GONE", "R-PE-BENCH.98/2", "patch.py:758: return immediately when the panel is gone", [node(S, "r_pe_bench_98_2_a_panel_gone_skips_the_tail_and_releases_record_done_exactly_once")])],
        "edits": [(
            P,
            "                if index and (\n                    self._patch_document_token() != token\n                    or not self.query(\"#patch_editor_panel\")\n                ):\n                    index = len(steps)\n                else:\n                    steps[index]()\n                    index += 1",
            "                if index and not self.query(\"#patch_editor_panel\"):\n                    return\n                if index and self._patch_document_token() != token:\n                    index = len(steps)\n                else:\n                    steps[index]()\n                    index += 1",
        )],
    },
}

MISSING = [
    ("I-APPLY-SYNC", "R-PE-DEF.62 / batch-48 LLR-081.3", "No existing node drives bytes-entry Apply and asserts same-call ledger/JSON/sheet repaint."),
    ("I-LOAD-SYNC", "R-PE-DEF.62 / batch-48 LLR-081.3", "No existing node drives the change-document load caller and asserts same-call repaint."),
    ("I-MOUNT-ONCE", "C9b-W mount contract", "No existing node counts StagingSheet.on_mount executions and asserts exactly once."),
]

EXPECTED_GROUP_ARMS = {
    "G01": 3, "G02": 1, "G03": 1, "G04": 1, "G05": 1, "G06": 1,
    "G07": 1, "G08": 1, "G09": 2, "G10": 2, "G11": 3, "G12": 3,
    "G13": 6, "G14": 2, "G15": 2, "G16": 2, "G17": 3, "G18": 2,
    "G19": 2, "G20": 1, "G21": 1, "G22": 1, "G23": 1,
}


class MutationError(RuntimeError):
    pass


def group_nodes(group_id):
    nodes = []
    for item in GROUPS[group_id]["controls"]:
        for test_node in item["nodes"]:
            if test_node not in nodes:
                nodes.append(test_node)
    return tuple(nodes)


def _newline_for(data):
    return "\r\n" if b"\r\n" in data else "\n"


def mutate_file(data, edits):
    text = data.decode("utf-8")
    newline = _newline_for(data)
    receipt = []
    for old, new in edits:
        old = old.replace("\n", newline)
        new = new.replace("\n", newline)
        count = text.count(old)
        if count != 1:
            raise MutationError(f"old anchor occurs {count} times")
        text = text.replace(old, new, 1)
        receipt.append(count)
    return text.encode("utf-8"), receipt


def mutations_for(tree, group_id):
    by_path = {}
    for path, old, new in GROUPS[group_id]["edits"]:
        by_path.setdefault(path, []).append((old, new))
    output = {}
    receipts = {}
    for path, edits in by_path.items():
        full = Path(tree) / path
        data = full.read_bytes()
        changed, counts = mutate_file(data, edits)
        if changed == data or sum(counts) == 0:
            raise MutationError("zero-applied mutation")
        output[path] = changed
        receipts[path] = counts
    if not output:
        raise MutationError("zero-applied mutation")
    return output, receipts


def apply_group(tree, group_id):
    output, receipts = mutations_for(tree, group_id)
    for path, data in output.items():
        (Path(tree) / path).write_bytes(data)
    return receipts


def validate_manifest():
    assert tuple(GROUPS) == tuple(EXPECTED_GROUP_ARMS)
    assert len(GROUPS) == 23
    assert sum(len(g["controls"]) for g in GROUPS.values()) == 26
    assert len(MISSING) == 3
    for group_id, expected in EXPECTED_GROUP_ARMS.items():
        assert len(group_nodes(group_id)) == expected, group_id
    assert sum(EXPECTED_GROUP_ARMS.values()) == 43
