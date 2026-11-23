# fastsim

Emulates the fast path of \sys (lock, Option A release, Option B validator verification) with one
Docker container per validator, real signatures, and `netem` delays between regions. Run it with
committee sizes of existing chains, then compare the measured latency against the consensus latency
those chains claim.

## Layout

| Path                                  | What |
|---------------------------------------|---|
| `src/validator.rs`                    | Validator algorithm, fast path only (Lock, LockQC release, Proof, SettleQC) |
| `src/client.rs`                       | Client algorithm. Locks, releases on a valid result (Option A), records timings |
| `src/provider.rs`                     | Provider algorithm. Forms the LockQC, "infers", sends the signed result, forms the SettleQC |
| `src/crypto.rs`                       | BLS12-381 votes and certificates (min_sig, as in Sui), Ed25519 for clients and providers |
| `src/net.rs`                          | Length-prefixed bincode frames over persistent TCP, one writer task per connection |
| `config/chains.csv`                   | Chain profiles: committee size, claimed consensus latency, source |
| `config/regions.csv`, `config/owd.csv` | Validator placement weights and inter-region RTTs |
| `gen.py`                              | Generates `deploy/<chain>/` (compose file, peers, one tc script per region) |
| `run.sh`                              | Runs one experiment and copies the CSVs to `results/` |
| `analyze.py`                          | Percentiles and comparison with 2 x the chain's consensus latency |

## What a run measures

The client runs `TASKS` tasks back to back (`CONCURRENCY` in flight). Per task, relative to the
client's Lock broadcast:

- **lock**: the client holds a LockQC
- **result**: the client holds `y` (Option A: from the provider; Option B: from a validator after the SettleQC)
- **paid**: the provider holds a SettleQC (shared host clock, so client and provider times are comparable)

`analyze.py` subtracts the simulated inference and proof verification from `paid` to get the protocol
overhead. A design that settles through consensus needs one ordered transaction to lock and one to
settle, so its overhead is at least 2 x the chain's consensus latency.

## Quick start

```bash
docker build -t fastsim .
./gen.py sui                          # deploy/sui: 128 validators over 6 regions
./run.sh sui A                        # Option A
PROOF_BYTES=8000 ./run.sh sui B
./analyze.py results/*
```

`./target/release/fastsim bench 654` prints the CPU cost of signing, vote checking and certificate
verification for a committee size.

## Parameters

Set as environment variables for `run.sh`.

| Variable | Default | Meaning |
|---|---|---|
| `OPTION` | A | set by `run.sh`'s second argument |
| `TASKS`, `CONCURRENCY` | 200, 1 | tasks per run and tasks in flight |
| `Y_BYTES`, `PROOF_BYTES` | 4096, 8192 | payload sizes actually sent over the network |
| `BW` | 1gbit | egress bandwidth of every node (htb) |
| `FORWARD` | 1 | Option A: forward SettleQCs to the validators (Option B always forwards) |
| `NETEM` | 1 | 0 skips the shaping, for smoke tests and the CPU floor |
| `WORKERS` | 1 | tokio threads per node |

Proof parameters from the proof-cost table (verification time, proof size):

| Scheme | `*_VERIFY_MS` | `PROOF_BYTES` |
|---|---|---|
| FlashProve | 17000 (24 cores) | 18800000 |
| zkLLM | 3950 | 188000 |
| TOPLOC | 81 | 8000 |
| Lightweight | 12 | 3400000 |

`gen.py` options: `--n` overrides the committee size, `--client-region` and `--provider-region`
place the two parties (defaults `euc1` and `use1`), `--jitter-ms` adds netem jitter (reorders
packets, so leave it at 0 unless that is what you want to study).

## Network model

Every node gets an IP in its region's /22. Its tc script puts one htb class per destination region
under a shared `BW` limit, with a netem qdisc that adds half the RTT. Delays are added on egress only,
so each direction gets half and a round trip gets the full RTT.

## Mapping to the paper

| Paper | Code |
|---|---|
| V-lockfresh, V-lockcheck, V-lockvote | `Validator::on_lock`, `coins_ok` |
| ValidQC, V-installlock | `Validator::lock_ok` (verified once per escrow, then cached) |
| V-release, VoteSettle | `on_release`, `vote_settle` |
| V-proofguard to V-voteb | `on_proof` |
| V-settlecheck, V-released, V-settled, V-delivery | `on_settled` |
| C-lock, C-check, C-release | `client.rs`, `start` and the `Proof` / `Verified` events |
| P-start, P-send, P-optionb, P-settleqc | `provider.rs` |

Not emulated, because they are off the latency path: the consensus unlock (Unlock, Report, UnlockQC),
slashing, the client's and validators' SettleQC forwards, and fee collection. In Option B the
provider sends the proof right after inference instead of waiting for the timer `t_p`.