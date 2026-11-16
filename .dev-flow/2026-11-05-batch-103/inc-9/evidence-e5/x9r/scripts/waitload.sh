#!/bin/bash
# waitload.sh: wait (2-min retries, up to 60 min) for the 1-min load < 2; prints the load read.
for i in $(seq 1 31); do l=$(cut -d' ' -f1 /proc/loadavg); awk "BEGIN{exit !($l < 2)}" && { echo $l; exit 0; }; sleep 120; done
echo "NOLOAD $l"; exit 1
