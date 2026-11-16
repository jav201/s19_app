#!/usr/bin/env bash
cd ~/work/zq-base2 || exit 3
awk -F'\t' '$2=="failed"' after/outcomes.tsv > evid2/after-failed.tsv
awk -F'\t' '$2=="failed"' ~/work/zq-i1b/after-pe/outcomes.tsv > evid2/before-failed.tsv
wc -l < evid2/after-failed.tsv; wc -l < evid2/before-failed.tsv
comm -12 <(cut -f1 evid2/after-failed.tsv) <(cut -f1 evid2/before-failed.tsv) | wc -l
