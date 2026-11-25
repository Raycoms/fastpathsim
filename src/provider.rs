//! Provider (Algorithm "Provider"): forms the LockQC, sends the signed result to the client
//! (Option A) or to the validators (Option B) right away, and forms the SettleQC. Once all its tasks
//! are paid, it appends its average timing to results/providers.csv.

use crate::config::{pair_key, Config};
use crate::crypto::{ed_sign, Committee, Votes};
use crate::msg::*;
use crate::net::{self, broadcast, encode, now_us, send, Tx};
use std::collections::HashMap;
use tokio::sync::mpsc::unbounded_channel;

#[derive(Default)]
struct Run {
    task: Option<Task>,
    lock_votes: Votes,
    lock: Option<LockQc>,
    settle_votes: HashMap<u64, Votes>,
    settled: bool,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let pair = cfg.pair;
    let (ev_tx, mut ev_rx) = unbounded_channel::<Msg>();
    let mut validators: Vec<Tx> = vec![];
    for &addr in &cfg.validators {
        let (r, tx) = net::connect(addr, Role::Provider, pair).await;
        let e = ev_tx.clone();
        net::read_loop(r, move |m| {
            let _ = e.send(m);
        });
        validators.push(tx);
    }
    let (r, client) = net::connect(cfg.clients[pair], Role::Provider, pair).await;
    net::read_loop(r, move |m| {
        let _ = ev_tx.send(m);
    });
    eprintln!("provider {pair}: connected to {} validators and the client", validators.len());

    let committee = Committee::new(cfg.validators.len());
    let sk = pair_key("provider", pair);
    let mut lock_times: HashMap<Id, u64> = HashMap::new();
    // Paid tasks, and sums over the measured ones (after warmup), in microseconds.
    let (mut paid, mut samples, mut paid_sum) = (0usize, 0u64, 0u64);
    let (mut first_lock, mut last_paid) = (u64::MAX, 0u64);
    // The tasks agreed during negotiation, which happens before the protocol.
    let mut runs: HashMap<Id, Run> = (0..cfg.tasks as u64)
        .map(|i| Task::agreed(pair, i, cfg.client_pks[pair], cfg.provider_pks[pair]))
        .map(|t| (t.id(), Run { task: Some(t), ..Default::default() }))
        .collect();
    let (y, pi) = (vec![1u8; cfg.y_bytes], vec![2u8; cfg.proof_bytes]);

    while let Some(m) = ev_rx.recv().await {
        match m {
            // Once locked, send the signed result right away (P-start, P-send, P-optionb).
            Msg::LockVote { id, signer, sig } => {
                let Some(r) = runs.get_mut(&id) else { continue };
                let Some(qc) = r.lock_votes.add(&committee, &lock_msg(&id), signer, &sig) else { continue };
                let lock = LockQc { task: r.task.clone().unwrap(), qc };
                r.lock = Some(lock.clone());
                lock_times.insert(id, now_us());
                let sig = ed_sign(&sk, &proof_msg(&id, &y, &pi));
                let m = Msg::Proof(Proof { lock, y: y.clone(), pi: pi.clone(), sig });
                if cfg.option_b {
                    broadcast(&validators, &m);
                } else {
                    send(&client, &encode(&m));
                }
            }
            Msg::SettleVote { id, value, signer, sig } => {
                let Some(r) = runs.get_mut(&id) else { continue };
                let Some(lock) = r.lock.clone() else { continue };
                if r.settled || (value != lock.task.amount + G_P && value != lock.task.amount) {
                    continue;
                }
                let votes = r.settle_votes.entry(value).or_default();
                if let Some(qc) = votes.add(&committee, &settle_msg(&id, value), signer, &sig) {
                    r.settled = true;
                    let (now, locked) = (now_us(), lock_times[&id]);
                    paid += 1;
                    if paid > cfg.warmup_tasks {
                        samples += 1;
                        paid_sum += now - locked;
                        first_lock = first_lock.min(locked);
                        last_paid = last_paid.max(now);
                    }
                    if paid == cfg.tasks {
                        let avg_ms = paid_sum as f64 / samples.max(1) as f64 / 1000.0;
                        let tput = samples as f64 / ((last_paid.saturating_sub(first_lock)) as f64 / 1e6).max(1e-9);
                        cfg.append_summary("providers.csv", &format!("{samples},{avg_ms:.1},{tput:.2}"))?;
                    }
                    // Option B needs the forward: validators deliver y once they see the SettleQC.
                    if cfg.forward || cfg.option_b {
                        broadcast(&validators, &Msg::Settled { lock, settle: SettleQc { id, value, qc } });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}   