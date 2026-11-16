#!/bin/bash
# waitload.sh: wait (15 s steps, up to 90 min) for the 1-min load < 2; prints the load read.
for i in $(seq 1 360); do l=$(cut -d' ' -f1 /proc/loadavg); awk "BEGIN{exit !($l < 2)}" && { echo $l; exit 0; }; sleep 15; done
echo "NOLOAD $l"; exit 1
