#!/usr/bin/env python3

import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def grouped(path):
    runs = defaultdict(list)
    if path.exists():
        for row in csv.DictReader(open(path)):
            runs[row["run"]].append(row)
    return runs


def avg(rows, col):
    """Average weighted by the number of measured tasks of each pair."""
    n = sum(int(r["samples"]) for r in rows)
    return sum(float(r[col]) * int(r["samples"]) for r in rows) / max(n, 1)


def main():
    folder = Path(sys.argv[1])
    chains = {c["name"]: c for c in csv.DictReader(open(ROOT / "config" / "chains.csv"))}
    clients, providers = grouped(folder / "clients.csv"), grouped(folder / "providers.csv")
    print("| run | n | option | proof | pairs | conc | tasks/s | lock | result | settle | paid | 2 x consensus | speedup |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for run, rows in clients.items():
        first = rows[0]
        # The run name starts with the chain name, which may itself contain dashes.
        chain = max((c for c in chains if run.startswith(c + "-")), key=len, default=None)
        cons = chains[chain]["consensus_ms"] if chain else ""
        settle = avg(rows, "settle_ms")
        paid = f"{avg(providers[run], 'lock_to_paid_ms'):.0f}" if providers.get(run) else "n/a"
        base = f"{2 * float(cons):.0f}" if cons else "n/a"
        speedup = f"{2 * float(cons) / settle:.1f}x" if cons and settle > 0 else "n/a"
        missing = "" if len(rows) == int(first["pairs"]) else f" ({len(rows)} of {first['pairs']} clients)"
        print(
            f"| {run}{missing} | {first['n']} | {first['option']} | {first['proof_bytes']} | {first['pairs']} "
            f"| {first['concurrency']} | {sum(float(r['tasks_per_s']) for r in rows):.1f} "
            f"| {avg(rows, 'lock_ms'):.0f} | {avg(rows, 'result_ms'):.0f} | {settle:.0f} | {paid} | {base} | {speedup} |"
        )
    print("\nAll times in ms, from the client's Lock broadcast, except paid: from the provider's LockQC to its SettleQC.")


if __name__ == "__main__":
    main()