#!/bin/bash
cd ~/work/zq-fx9d; until grep -q CHAIN2_DONE out/chain2-log.txt; do sleep 20; done; ./chain3.sh
