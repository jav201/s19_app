| Id | Requirement / code | File | Original nodes | Final | Killing node (or note) |
|---|---|---|---|---|---|
| w01 | R-PE-BENCH.1 subtitle back to Inc 8's | layout.py | killed | killed | test_r_pe_bench_1_1_the_sheet_window_subtitle_names_the_bench[118x54] |
| w03a | R-PE-BENCH.3 editable=True (not a callable) | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w03b | R-PE-BENCH.3 detail = Inc 8's no-editor tail | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_ |
| w03c | R-PE-BENCH.3 array kind not a bench kind | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w03d | R-PE-BENCH.3 label stays Inc 8's | bench_sheet.py | killed | killed | test_r_pe_bench_3_4_after_import_the_three_bench_kinds_are_registered |
| w05 | R-PE-BENCH.5 geometry room not reduced by the window line (widget) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_5_2_the_cursor_stays_on_a_painted_row_while_it_walks_down_a_tall_grid |
| w06 | R-PE-BENCH.6 stage advances the selection | patch.py | survived | killed (new node) | test_r_pe_bench_6_2_a_record_stage_keeps_the_selection_on_a_row_that_has_another_row_below_it |
| w09a | R-PE-BENCH.9 fresh state at every selection message | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged |
| w09b | CODE show_page: shown-rows filter never drops | bench_sheet.py | killed | killed | test_r_pe_bench_9_3_a_page_without_the_row_drops_its_state |
| w09c | CODE show_page: shown-rows filter drops the shown | bench_sheet.py | killed | killed | test_r_pe_bench_9_1_a_filter_keystroke_that_keeps_the_row_keeps_its_state |
| w09d | CODE show_page: filter by the whole population (pre-F-M9 reading) | bench_sheet.py | killed | killed | test_r_pe_bench_9_3_a_page_without_the_row_drops_its_state |
| w20 | R-PE-BENCH.20 decode not requested at selection | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w22a | R-PE-BENCH.22 stale decode painted (decode token not checked) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_3_a_decode_made_stale_by_the_selection_key_alone_runs_again_for_the_selected |
| w22b | CODE stale-decode requeue: any row, not only the selected | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_4_a_stale_decode_of_a_row_no_longer_selected_is_not_run_again |
| w22c | CODE stale-decode requeue removed | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_3_a_decode_made_stale_by_the_selection_key_alone_runs_again_for_the_selected |
| w22d | CODE stale-decode requeue: queues a second decode | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_5_a_stale_decode_of_the_selected_row_adds_no_second_queued_decode |
| w22e | CODE stale-decode requeue at the back of the slot | bench_sheet.py | survived | survived, argued equivalent | order of two independent queued jobs (decode, preview) that both end before the sheet settles; no settled output differs |
| w23a | R-PE-BENCH.23 summaries not in page order | bench_sheet.py | killed | killed | test_r_pe_bench_23_1_the_page_is_summarised_off_the_ui_thread_in_page_order |
| w23b | R-PE-BENCH.23 summary of a LARGE row on page change | bench_sheet.py | killed | killed | test_r_pe_bench_22_1_and_2_a_decode_ended_after_the_selection_moved_is_discarded |
| w24 | R-PE-BENCH.24 summary of an older page painted | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_24_2_a_summary_ended_after_the_page_turned_is_not_painted |
| w25a | R-PE-BENCH.25 recompute every row on a document change | bench_sheet.py | killed | killed | test_r_pe_bench_25_2_a_raw_entry_over_one_row_marks_that_row_and_decodes_no_other |
| w25b | R-PE-BENCH.25 no recompute for a row whose staged differs (undo) | bench_sheet.py | survived | survived, argued equivalent | the delta cell and the `staged` word read `row.is_staged` (the document), which an undo clears; a stale `staged` on a row that is not selected is rebuilt by the decode job at its next selection, so every observable output is equal |
| w25c | R-PE-BENCH.25 no recompute for a row holding an entry | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_25_3_a_raw_entry_over_a_row_that_is_not_selected_gives_it_a_staged_delta |
| w25d | R-PE-BENCH.25 selected row: staged recompute dropped | bench_sheet.py | killed | killed | test_r_pe_bench_15_16_18_the_painted_row_shows_mark_new_count_and_delta_after_an_apply_and_a_st |
| w27a | R-PE-BENCH.27 apply over no values (job check only) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_27_3_a_tool_applied_to_a_row_whose_decode_was_refused_changes_nothing_and_does_ |
| w27b | CODE stage check: none at all | bench_sheet.py | killed | killed | test_r_pe_bench_27_apply_or_stage_while_the_values_decode_shows_the_still_decoding_status[stage |
| w27c | CODE stage check: refuse while the job is a decode (pre-F-M9-1 reading) | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w28a | R-PE-BENCH.28 several jobs at once | bench_sheet.py | killed | killed | test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale |
| w28b | R-PE-BENCH.28 job starts while a record hold is up | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| w40 | R-PE-BENCH.40 Enter focuses the op input first | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE |
| w44a | R-PE-BENCH.44 d selects Set | bench_sheet.py | killed | killed | test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[s] |
| w44b | R-PE-BENCH.44 i not bound | bench_sheet.py | killed | killed | test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[i] |
| w44c | R-PE-BENCH.44 tool action ignores the key | bench_sheet.py | killed | killed | test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run[i] |
| w45 | R-PE-BENCH.45 Enter in bench focus does not reach the op input | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE |
| w46a | R-PE-BENCH.46 Escape keeps the bench focus | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w46b | R-PE-BENCH.46 Escape not bound on the sheet | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w47a | R-PE-BENCH.47 op-input Escape leaves the bench focus off | bench_sheet.py | killed | killed | test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown[R-PE |
| w47b | R-PE-BENCH.47 op-input Escape does not move focus to the body | bench_sheet.py | killed | killed | test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too |
| w48a | R-PE-BENCH.48 alt+s refused from the op input | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_48_3_alt_s_from_an_op_input_the_bench_does_not_hold_the_focus_on_still_stages |
| w48b | R-PE-BENCH.48 alt+s not bound | bench_sheet.py | killed | killed | test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol |
| w49a | R-PE-BENCH.49 cursor/page/tool/escape actions enabled without the bench focus | bench_sheet.py | killed | killed | test_r_pe_bench_49_1_off_the_bench_the_keys_reach_the_app[DISPLAY_0001-s] |
| w49b | R-PE-BENCH.49 tool action not gated | bench_sheet.py | killed | killed | test_r_pe_bench_49_1_off_the_bench_the_keys_reach_the_app[DISPLAY_0001-s] |
| w49c | R-PE-BENCH.49 stage_record enabled on any bench row | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_49_3_alt_s_off_the_bench_and_off_the_op_input_stages_nothing |
| w51 | R-PE-BENCH.51 apply path loses the refusal status | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_62_6_a_refused_operand_shows_its_status_with_the_operand_echo[abc] |
| w51b | R-PE-BENCH.51 apply request not stopped | bench_sheet.py | survived | survived, argued equivalent | `event.stop()`: the apply request has no handler above the sheet, so bubbling it changes nothing a user or the document sees |
| w66a | R-PE-BENCH.66 no preview queued on an edit change | bench_sheet.py | killed | killed | test_r_pe_bench_71_1_and_2_the_second_stage_encodes_over_the_first_one |
| w66b | R-PE-BENCH.66/.71 encode over the image, not the overlay | bench_sheet.py | killed | killed | test_r_pe_bench_71_1_and_2_the_second_stage_encodes_over_the_first_one |
| w66c | R-PE-BENCH.66 preview of an emptied edit kept | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_66_5_undoing_the_only_edit_clears_the_bytes_line |
| w66d | R-PE-BENCH.66 'encoding' placeholder not set | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_66_6_the_bytes_line_says_encoding_while_the_preview_runs |
| w70a | R-PE-BENCH.70 next job starts before the app's write (no hold) | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| w70b | R-PE-BENCH.70 record_done does not release the hold | bench_sheet.py | killed | killed | test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale |
| w70c | R-PE-BENCH.70 record_staged never clears the edit | bench_sheet.py | killed | killed | test_r_pe_bench_25_1_undo_of_a_record_stage_removes_the_staged_dot |
| w70d | R-PE-BENCH.70 a queued record of a row keeps the first edit | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_6_a_second_alt_s_before_the_first_record_starts_stages_the_newer_edit |
| w72 | R-PE-BENCH.72 value word always plural | change_service.py | killed | killed | test_r_pe_bench_72_1_and_70_1_stage_record_writes_one_bytes_entry_and_words_the_status |
| w72b | R-PE-BENCH.72 shown text is the count only | change_service.py | killed | killed | test_r_pe_bench_72_1_and_70_1_stage_record_writes_one_bytes_entry_and_words_the_status |
| w73a | R-PE-BENCH.73 notices dropped | change_service.py | killed | killed | test_r_pe_bench_73_1_two_notices_make_one_line_with_the_count_of_the_rest |
| w73b | R-PE-BENCH.73 the rest counted wrongly | change_service.py | killed | killed | test_r_pe_bench_73_1_two_notices_make_one_line_with_the_count_of_the_rest |
| w73c | R-PE-BENCH.73 suffix always shown | change_service.py | killed | killed | test_r_pe_bench_73_2_one_notice_has_no_suffix |
| w74a | R-PE-BENCH.74 refusal not checked | patch.py | killed | killed | test_r_pe_bench_74_a_refused_encode_shows_its_message_and_leaves_document_and_edit_unchanged[74 |
| w74b | R-PE-BENCH.74 span check dropped | patch.py | survived | killed (new node) | test_r_pe_bench_74_2_a_record_encoded_outside_its_span_is_not_staged |
| w75 | R-PE-BENCH.75 empty edit staged | bench_sheet.py | killed | killed | test_r_pe_bench_75_1_alt_s_with_an_empty_bench_edit_says_so_and_writes_nothing |
| w76 | R-PE-BENCH.76 no A2L not checked | patch.py | killed | killed | test_r_pe_bench_76_1_no_a2l_when_the_stage_acts_says_so |
| w77a | R-PE-BENCH.77 definition compared by address only | patch.py | killed | killed | test_r_pe_bench_77_a_definition_changed_since_the_bench_was_built_is_refused[77-2-reshaped-MATR |
| w77b | R-PE-BENCH.77 definition change not checked | patch.py | killed | killed | test_r_pe_bench_77_a_definition_changed_since_the_bench_was_built_is_refused[77-1-moved-VAL_BLK |
| w78a | R-PE-BENCH.78 generation not checked | patch.py | survived | killed (new node) | test_r_pe_bench_78_3_a_request_made_for_an_older_document_is_not_staged |
| w78b | R-PE-BENCH.78 an image change does not bump the generation | bench_sheet.py | killed | killed | test_r_pe_bench_78_2_an_image_push_during_the_held_encode_makes_the_result_stale |
| w78c | R-PE-BENCH.78 a document-only change does not bump the generation | bench_sheet.py | killed | killed | test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale |
| w79a | R-PE-BENCH.79 stage keeps the edit | bench_sheet.py | killed | killed | test_r_pe_bench_25_1_undo_of_a_record_stage_removes_the_staged_dot |
| w79b | R-PE-BENCH.79 stage clears whatever the edit is | bench_sheet.py | killed | killed | test_r_pe_bench_79_2_an_edit_made_while_the_record_encodes_is_kept_with_its_diamond |
| w83a | R-PE-BENCH.83 no busy check | patch.py | killed | killed | test_r_pe_bench_83_1_a_session_action_running_refuses_the_stage_with_the_busy_line |
| w92a | R-PE-BENCH.92 name echoed raw in the changed-in-A2L status | patch.py | survived | killed (new node) | test_r_pe_bench_92_4_the_changed_in_the_a2l_status_echoes_a_300_character_name_in_256 |
| w92b | R-PE-BENCH.92 name echoed raw in the still-decoding (stage) status | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_92_3_the_still_decoding_status_of_a_stage_echoes_a_300_character_name_in_256 |
| w92c | R-PE-BENCH.92 name echoed raw in the no-edit status | bench_sheet.py | killed | killed | test_r_pe_bench_92_1_a_300_character_name_is_echoed_as_256_characters_and_an_ellipsis |
| w92d | R-PE-BENCH.92 name echoed raw in the stale-record status | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_92_2_the_stale_record_status_echoes_a_300_character_name_in_256 |
| w15a | R-PE-BENCH.15/16/18 sheet.py: no state passed to row_line (F-W1) | sheet.py | killed | killed | test_r_pe_bench_23_1_the_page_is_summarised_off_the_ui_thread_in_page_order |
| w15b | sheet.py pending default restored to Inc 8's empty string | sheet.py | survived | killed (Inc 8 node) | test_b103_inc8_s2_sheet_rows.py::test_r_pe_def_24_3_a_text_row_left_with_its_row_fill_unchanged_is_not_pend... |
| c01 | CODE canvas_shape: room-5 branch uses room-4 | definition_bench_view.py | killed | killed | test_r_pe_bench_38_6_the_bytes_line_stays_last_while_the_window_line_shows[8] |
| c02 | CODE canvas_shape: room-5 branch uses room-6 | definition_bench_view.py | survived | killed (new node) | test_r_pe_bench_5_3_a_windowed_tall_grid_fills_its_room_and_its_window_line_counts_the_painted_ |
| c03 | CODE canvas_shape: window-line test inverted | definition_bench_view.py | killed | killed | test_r_pe_bench_38_6_the_bytes_line_stays_last_while_the_window_line_shows[8] |
| c04 | CODE canvas_shape: first reserve is 3 | definition_bench_view.py | killed | killed | test_r_pe_bench_38_5_the_bytes_line_stays_last_while_the_whole_grid_fits[10] |
| c05 | CODE canvas_shape: second shape not recomputed | definition_bench_view.py | survived | killed (new node) | test_r_pe_bench_5_2_the_cursor_stays_on_a_painted_row_while_it_walks_down_a_tall_grid |
| s01 | CODE _staged_pair: always a second decode | bench_sheet.py | killed | killed | test_r_pe_bench_22_1_and_2_a_decode_ended_after_the_selection_moved_is_discarded |
| s02 | CODE _staged_pair: never a second decode | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry |
| s03 | CODE _staged_pair: entry end boundary inclusive | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_28_3_an_entry_outside_the_record_costs_the_decode_job_no_second_decode[0x80008E |
| s04 | CODE _staged_pair: entry start boundary inclusive | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| s05 | CODE _staged_pair: empty span | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry |
| s06 | CODE _staged_pair: any entry counts as overlapping | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write |
| s07 | CODE _staged_pair: None as staged | bench_sheet.py | survived | survived, argued equivalent | `staged` None versus equal to the current values for a row no entry overlaps: every reader of `staged` first needs `row.is_staged`, which needs an overlapping entry |
| s08 | CODE _staged_pair: staged decoded over the image | bench_sheet.py | survived | killed (new node) | test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry |
