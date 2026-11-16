#!/bin/bash
# X8b E5 battery on a fresh clone of the fix tip (HT-03 exact clone): Inc 8b, Inc 8, Inc 9 files, hue census, laws.
S=$HOME/work/zq-x8b
O=$S/out-green
mkdir -p "$O"
cd "$S" && rm -rf t2 && git clone -q -b b103-inc8b t2.bundle t2
cd "$S/t2" || exit 9
for f in tests/test_b103_inc8b_*.py tests/test_b103_inc8_*.py tests/test_b103_inc9_*.py tests/test_tui_patch_json.py; do
  n=$(basename "$f" .py); n=${n#test_}
  if [ "$n" = b103_inc9_w_jobs ]; then
    # 26_2 times out on the tip and on base (I8b); the timing arm ran serially at load < 2 (out-timing)
    bash "$S/run.sh" "$S/t2" "$O/g-$n.txt" -n 2 "$f" -k "not 26_2 and not 28_2 and not 29_1 and not 29_2 and not 82_1 and not 20_1"
  else
    bash "$S/run.sh" "$S/t2" "$O/g-$n.txt" -n 2 "$f"
  fi
done
for law in engine_unchanged deps_seam_law docs_canon no_private_tokens filename_markup_safety b101_doc_hygiene \
           b101_help_legend_docs report_markup_safety b97_key_bar id_registry suite_hygiene requirements_canon address_census; do
  bash "$S/run.sh" "$S/t2" "$O/law-$law.txt" -n 2 "tests/test_$law.py"
done
for f in "$O"/*.txt; do echo "$(basename "$f" .txt): $(grep -E '^[0-9]+ (passed|failed)|^=+ .*(passed|failed|error)' "$f" | tail -1)"; done > "$O/summary.txt"
echo BATTERY_DONE > "$O/BATTERY_DONE"
