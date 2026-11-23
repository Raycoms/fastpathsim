#!/usr/bin/env bash
# Sweep: every chain (or the ones given), both placements, both options, and the proof sizes of the
# proof-cost table. Results go to results/sweep-<time>/, with a summary in summary.md and summary.csv.
#
#   ./run.sh                  all chains in config/chains.csv except local
#   ./run.sh sui cosmoshub    only these chains
#
# Override the sweep with WEIGHTS, OPTIONS and PROOFS, e.g. PROOFS="8000" OPTIONS="A" ./run.sh sui.
# TASKS (default 100) and the other knobs of run_one.sh apply to every run.
set -uo pipefail
cd "$(dirname "$0")"

if [ $# -gt 0 ]; then chains="$*"; else chains=$(tail -n +2 config/chains.csv | cut -d, -f1 | grep -vx local); fi
weights=${WEIGHTS:-"eth sol"}
options=${OPTIONS:-"A B"}
# Proof sizes in bytes: TOPLOC, zkLLM, Lightweight, FlashProve.
proofs=${PROOFS:-"8000"} # 188000 3400000 18800000"}
export TASKS=${TASKS:-100}

sweep=results/sweep-$(date +%Y%m%d-%H%M%S)
mkdir -p "$sweep"
total=$(( $(wc -w <<<"$chains") * $(wc -w <<<"$weights") * $(wc -w <<<"$options") * $(wc -w <<<"$proofs") ))
i=0
for chain in $chains; do
  for w in $weights; do
    for proof in $proofs; do
      for opt in $options; do
        i=$((i + 1))
        name=$chain-$w-$opt-$proof
        echo "[$i/$total] $name"
        if ! PROOF_BYTES=$proof OUT=$sweep/$name ./run_one.sh "$chain" "$opt" "$w" >/dev/null; then
          echo "  failed (logs above), listed in $sweep/failed.txt"
          echo "$name" >> "$sweep/failed.txt"
        fi
      done
    done
  done
done

./analyze.py "$sweep"/*/ > "$sweep/summary.md"
./analyze.py --csv "$sweep"/*/ > "$sweep/summary.csv"
cat "$sweep/summary.md"