#!/usr/bin/env bash
# Law 070_2 on tip / merged / base with two HOME basenames (<iso-home> per HT-02, and an unused one).
set -u
S=$HOME/work/zq-base2
cd "$S" || exit 3
sed 's#home/<iso-home>#home/$HB#g' run_t.sh > run_t2.sh
N=tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
for t in tip merged base; do
  for hb in <iso-home> qhome7; do
    HB=$hb bash run_t2.sh "$S/$t" "$S/out-l070-$t-$hb" 0 300 "$N"
    echo "$t $hb rc=$(cat "$S/out-l070-$t-$hb/rc")"
    grep -E '^E +[a-z0-9-]+/' "$S/out-l070-$t-$hb/run.txt" | sed -E 's/^E +/    /' | sort -u
  done
done
