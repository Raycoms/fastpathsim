#!/usr/bin/env python3
"""Summarize runs and compare them with the chain's claimed consensus latency.

usage: ./analyze.py [--csv] results/<run> [results/<run> ...]

Per task, relative to the client's Lock broadcast (t0):
  lock      client holds the LockQC
  result    client holds y
  paid      provider holds the SettleQC
A consensus-based design needs one ordered transaction to lock and one to settle, so it takes at
least 2 x the chain's consensus latency for the same steps.
"""

import csv
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WARMUP = 5  # tasks dropped at the start of each run


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))]


def load(run):
    params = dict(l.strip().split("=", 1) for l in open(run / "params.env") if "=" in l)
    client = list(csv.DictReader(open(run / "client.csv")))[WARMUP:]
    provider = {r["id"]: r for r in csv.DictReader(open(run / "provider.csv"))}
    rows = []
    for c in client:
        p = provider.get(c["id"])
        if not p:
            continue
        t0 = int(c["t0_us"])
        ms = lambda us: (int(us) - t0) / 1000
        rows.append({"lock": ms(c["lock_us"]), "result": ms(c["result_us"]), "paid": ms(p["settle_us"])})
    return params, rows


COLS = ["chain", "n", "weights", "option", "proof_bytes", "lock_p50", "result_p50", "paid_p50", "paid_p90",
        "paid_p99", "consensus_x2", "kind", "speedup"]


def main():
    args = sys.argv[1:]
    as_csv = "--csv" in args
    runs = [Path(a) for a in args if a != "--csv" and (Path(a) / "params.env").exists()]
    chains = {c["name"]: c for c in csv.DictReader(open(ROOT / "config" / "chains.csv"))}
    out = csv.writer(sys.stdout) if as_csv else None
    if as_csv:
        out.writerow(COLS)
    else:
        print("| chain | n | weights | option | proof | lock p50 | result p50 | paid p50 / p90 / p99 | 2 x consensus | kind | speedup |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
    for run in runs:
        params, rows = load(run)
        if not rows:
            if not as_csv:
                print(f"| {run.name} | no complete tasks |")
            continue
        chain = chains.get(params.get("chain", ""), {})
        option = params.get("OPTION", "A")
        paid = [r["paid"] for r in rows]
        p50 = statistics.median(paid)
        cons = chain.get("consensus_ms")
        base = 2 * float(cons) if cons else None
        row = {
            "chain": params.get("chain", "?"),
            "n": params.get("n", chain.get("n", "?")),
            "weights": params.get("weights", "eth"),
            "option": option,
            "proof_bytes": params.get("PROOF_BYTES", "?"),
            "lock_p50": round(statistics.median(r["lock"] for r in rows)),
            "result_p50": round(statistics.median(r["result"] for r in rows)),
            "paid_p50": round(p50),
            "paid_p90": round(pct(paid, 90)),
            "paid_p99": round(pct(paid, 99)),
            "consensus_x2": round(base) if base else "",
            "kind": chain.get("kind", ""),
            "speedup": round(base / p50, 1) if base and p50 > 0 else "",
        }
        if as_csv:
            out.writerow(row[c] for c in COLS)
        else:
            r = row
            print(
                f"| {r['chain']} | {r['n']} | {r['weights']} | {r['option']} | {r['proof_bytes']} "
                f"| {r['lock_p50']} | {r['result_p50']} | {r['paid_p50']} / {r['paid_p90']} / {r['paid_p99']} "
                f"| {r['consensus_x2'] or 'n/a'} | {r['kind']} | {str(r['speedup']) + 'x' if r['speedup'] else 'n/a'} |"
            )
    if not as_csv:
        print("\nAll times in ms. Speedup = 2 x consensus / paid p50.")


if __name__ == "__main__":
    main()