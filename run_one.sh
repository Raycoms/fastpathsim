#!/usr/bin/env bash
# One experiment: ./run_one.sh CHAIN OPTION [WEIGHTS]   (OPTION A or B, WEIGHTS eth or sol)
# Other knobs are environment variables, e.g. TASKS=100 PAIRS=10 PROOF_BYTES=188000 ./run_one.sh sui B sol
# Every client and provider appends its averages to clients.csv and providers.csv in results/OUT
# (default run-<date>-<time>), labelled with RUN (default CHAIN-WEIGHTS).
set -euo pipefail
chain=$1
export OPTION=$2
weights=${3:-eth}
export RUN=${RUN:-$chain-$weights}
export OUT=${OUT:-run-$(date +%Y%m%d-%H%M%S)}
dir=deploy/$chain
pairs=${PAIRS:-1}
./gen.py "$chain" --weights "$weights" --pairs "$pairs" >/dev/null

# All containers share the host's ARP table. Each client and provider talks to every validator, so the
# run needs about 4 x n x pairs entries. Beyond the host's limit, new connections silently stall.
n=$(grep -c ^validator "$dir/peers.txt")
need=$((4 * n * pairs + 128))
have=$(cat /proc/sys/net/ipv4/neigh/default/gc_thresh3)
if [ "$have" -lt "$need" ]; then
  echo "ARP table limit $have is below the $need entries this run needs. Raise it on the host:" >&2
  echo "  sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=$need net.ipv4.neigh.default.gc_thresh2=$((2 * need)) net.ipv4.neigh.default.gc_thresh3=$((4 * need))" >&2
  exit 1
fi

res=results/$OUT
mkdir -p "$res"
cols=run,pair,n,option,pairs,concurrency,tasks,proof_bytes,samples
[ -s "$res/clients.csv" ] || echo "$cols,lock_ms,result_ms,settle_ms,tasks_per_s" > "$res/clients.csv"
[ -s "$res/providers.csv" ] || echo "$cols,lock_to_paid_ms,tasks_per_s" > "$res/providers.csv"

dc() { docker compose -f "$dir/docker-compose.yml" "$@"; }
# Stop leftovers of an earlier or interrupted run of this chain, which may have had more pairs.
dc down -t 1 --remove-orphans >/dev/null 2>&1 || true
trap 'dc down -t 1 --remove-orphans >/dev/null 2>&1 || true' EXIT
dc up -d --quiet-pull --remove-orphans >/dev/null 2>&1
clients=$(dc config --services | grep '^client')
codes=$(docker wait $(dc ps -aq $clients))
[ -z "$(grep -vx 0 <<<"$codes")" ] || { dc logs client0 provider0 | tail -n 20; echo "a client failed: $codes"; exit 1; } >&2
sleep 1  # let the providers write their lines