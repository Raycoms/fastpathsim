#!/usr/bin/env bash
# One experiment: ./run_one.sh CHAIN OPTION [WEIGHTS]   (OPTION A or B, WEIGHTS eth or sol)
# Other knobs are environment variables, e.g. TASKS=100 PROOF_BYTES=188000 ./run_one.sh sui B sol
# OUT sets the result directory.
set -euo pipefail
chain=$1
export OPTION=$2
weights=${3:-eth}
dir=deploy/$chain
./gen.py "$chain" --weights "$weights" >/dev/null
rm -f "$dir"/results/*.csv
out=${OUT:-results/$chain-$weights-$OPTION-${PROOF_BYTES:-8192}-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out"

dc() { docker compose -f "$dir/docker-compose.yml" "$@"; }
trap 'dc down -t 1 >/dev/null 2>&1 || true' EXIT
dc up -d --quiet-pull >/dev/null 2>&1
code=$(docker wait "$(dc ps -aq client)")
[ "$code" = 0 ] || { dc logs client provider | tail -n 20; echo "client exited with $code"; exit 1; } >&2
sleep 1  # let the provider write its last line

cp "$dir"/results/*.csv "$out"/
{
  env | grep -E '^(OPTION|TASKS|CONCURRENCY|Y_BYTES|BW|FORWARD|NETEM)=' || true
  echo "PROOF_BYTES=${PROOF_BYTES:-8192}"
  echo "chain=$chain"
  echo "weights=$weights"
  echo "n=$(grep -c ^validator "$dir/peers.txt")"
} > "$out/params.env"
echo "$out"