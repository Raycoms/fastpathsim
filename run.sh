#!/usr/bin/env bash
# Sweep: every chain (or the ones given), both placements, both options, and the proof sizes of the
# proof-cost table. Every client and provider appends its averages to clients.csv and providers.csv
# in results/run-<date>-<time>/. The run column names the run, e.g. sui-eth-A-8000-p10-c1-t100.
#
#   ./run.sh                  all chains in config/chains.csv except local
#   ./run.sh sui cosmoshub    only these chains
#
# Override the sweep with WEIGHTS, OPTIONS, PROOFS, PAIRS (client/provider pairs, default 1),
# CONCURRENCY (tasks in flight per client, default 1) and TASKS (tasks per client, default 100),
# e.g. PROOFS="8000" OPTIONS="A" PAIRS="1 10" CONCURRENCY="1 10" ./run.sh sui.
# The other knobs of run_one.sh apply to every run.
set -uo pipefail
cd "$(dirname "$0")"

if [ $# -gt 0 ]; then chains="$*"; else chains=$(tail -n +2 config/chains.csv | cut -d, -f1 | grep -vx local); fi
weights=${WEIGHTS:-"eth sol"}
options=${OPTIONS:-"A B"}
# Proof sizes in bytes: TOPLOC, zkLLM, Lightweight, FlashProve.
proofs=${PROOFS:-"8000"} # 188000 3400000 18800000"}
pairs_list=${PAIRS:-1 10 100}
conc_list=${CONCURRENCY:-1}
tasks_list=${TASKS:-100}
export OUT=run-$(date +%Y%m%d-%H%M%S)

total=$(( $(wc -w <<<"$chains") * $(wc -w <<<"$weights") * $(wc -w <<<"$options") * $(wc -w <<<"$proofs") * $(wc -w <<<"$pairs_list") * $(wc -w <<<"$conc_list") * $(wc -w <<<"$tasks_list") ))
i=0
for chain in $chains; do
  for w in $weights; do
    for proof in $proofs; do
      for pairs in $pairs_list; do
        for conc in $conc_list; do
          for tasks in $tasks_list; do
            for opt in $options; do
              i=$((i + 1))
              name=$chain-$w-$opt-$proof-p$pairs-c$conc-t$tasks
              echo "[$i/$total] $name"
              RUN=$name TASKS=$tasks CONCURRENCY=$conc PAIRS=$pairs PROOF_BYTES=$proof ./run_one.sh "$chain" "$opt" "$w" \
                || echo "  failed (logs above)"
            done
          done
        done
      done
    done
  done
done
./analyze.py "results/$OUT"