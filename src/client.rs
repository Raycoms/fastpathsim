//! Client (Algorithm "Client"): locks and releases on a valid result (Option A). At the end it
//! appends its average timings to results/clients.csv. The consensus unlock is not on the latency
//! path and is left out.

use crate::config::{pair_key, Config};
use crate::crypto::{ed_sign, ed_verify, Committee, Votes};
use crate::msg::*;
use crate::net::{self, broadcast, now_us, Tx};
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

enum Ev {
    Net(Msg),
}

struct Run {
    task: Task,
    t0: u64,
    lock_votes: Votes,
    lock: Option<LockQc>,
    settle_votes: HashMap<u64, Votes>,
    lock_us: u64,
    result_us: u64,
    settle_us: u64,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let (ev_tx, mut ev_rx) = unbounded_channel::<Ev>();
    let feed = |e: UnboundedSender<Ev>| move |m| {
        let _ = e.send(Ev::Net(m));
    };
    let pair = cfg.pair;
    let listener = TcpListener::bind(("0.0.0.0", cfg.clients[pair].port())).await?;

    let mut validators: Vec<Tx> = vec![];
    for &addr in &cfg.validators {
        let (r, tx) = net::connect(addr, Role::Client, pair).await;
        net::read_loop(r, feed(ev_tx.clone()));
        validators.push(tx);
    }
    // The provider connects to us once it is connected to all validators.
    let (stream, _) = listener.accept().await?;
    // Kept open: the provider sends its result over this connection.
    let (mut r, _provider) = net::split(stream);
    anyhow::ensure!(matches!(net::read_msg(&mut r).await?, Msg::Hello(Role::Provider, _)));
    net::read_loop(r, feed(ev_tx.clone()));
    eprintln!("client {pair}: connected to {} validators and the provider", validators.len());
    tokio::time::sleep(Duration::from_secs(cfg.warmup_s)).await;

    let committee = Committee::new(cfg.validators.len());
    let sk = pair_key("client", pair);
    // Sums over the measured tasks (after warmup), in microseconds.
    let (mut samples, mut lock_sum, mut result_sum, mut settle_sum) = (0u64, 0u64, 0u64, 0u64);
    let (mut first_t0, mut last_settle) = (u64::MAX, 0u64);

    let mut runs: HashMap<Id, Run> = HashMap::new();
    let (mut started, mut finished) = (0usize, 0usize);
    let start = |runs: &mut HashMap<Id, Run>, started: &mut usize| {
        let task = Task::agreed(pair, *started as u64, cfg.client_pks[pair], cfg.provider_pks[pair]);
        *started += 1;
        let id = task.id();
        let sig = ed_sign(&sk, &lock_msg(&id));
        let t0 = now_us();
        broadcast(&validators, &Msg::Lock { task: task.clone(), sig });
        runs.insert(id, Run { task, t0, lock_votes: Votes::default(), lock: None, settle_votes: HashMap::new(), lock_us: 0, result_us: 0, settle_us: 0 });
    };
    for _ in 0..cfg.concurrency.min(cfg.tasks) {
        start(&mut runs, &mut started);
    }

    while finished < cfg.tasks {
        let ev = match tokio::time::timeout(Duration::from_secs(60), ev_rx.recv()).await {
            Ok(Some(ev)) => ev,
            _ => {
                for r in runs.values() {
                    let settle: Vec<_> = r.settle_votes.iter().map(|(v, s)| (*v, s.len())).collect();
                    eprintln!(
                        "client {pair}: stuck task: {} lock votes, lock {}, result {}, settle votes {settle:?}",
                        r.lock_votes.len(), r.lock.is_some(), r.result_us != 0
                    );
                }
                anyhow::bail!("client {pair}: no progress for 60 s, {finished} of {} tasks done", cfg.tasks)
            }
        };
        let id = match ev {
            Ev::Net(Msg::LockVote { id, signer, sig }) => {
                // The first LockQC counts, whether formed here or taken from the provider's result.
                let Some(r) = runs.get_mut(&id).filter(|r| r.lock.is_none()) else { continue };
                if let Some(qc) = r.lock_votes.add(&committee, &lock_msg(&id), signer, &sig) {
                    r.lock = Some(LockQc { task: r.task.clone(), qc });
                    r.lock_us = now_us();
                }
                id
            }
            // Option A: verify the signed result, then release (C-check, C-release).
            Ev::Net(Msg::Proof(p)) => {
                let id = p.lock.task.id();
                let Some(r) = runs.get_mut(&id) else { continue };
                if r.result_us != 0 || !ed_verify(&r.task.provider, &proof_msg(&id, &p.y, &p.pi), &p.sig) {
                    continue;
                }
                if r.lock.is_none() && committee.verify_qc(&lock_msg(&id), &p.lock.qc) {
                    r.lock = Some(p.lock);
                    r.lock_us = now_us();
                }
                if r.lock.is_none() {
                    continue;
                }
                r.result_us = now_us();
                let sig = ed_sign(&sk, &release_msg(&id));
                broadcast(&validators, &Msg::Release { lock: r.lock.clone().unwrap(), sig });
                id
            }
            Ev::Net(Msg::SettleVote { id, value, signer, sig }) => {
                let Some(r) = runs.get_mut(&id) else { continue };
                if value != r.task.amount + G_P && value != r.task.amount {
                    continue;
                }
                let votes = r.settle_votes.entry(value).or_default();
                if votes.add(&committee, &settle_msg(&id, value), signer, &sig).is_some() && r.settle_us == 0 {
                    r.settle_us = now_us();
                }
                id
            }
            // Option B: validators deliver the withheld result once a SettleQC exists.
            Ev::Net(Msg::Result { id, .. }) => {
                let Some(r) = runs.get_mut(&id) else { continue };
                if r.result_us == 0 {
                    r.result_us = now_us();
                }
                id
            }
            _ => continue,
        };
        // Done once the client holds the LockQC, the result and the SettleQC (in Option B these can
        // arrive in any order).
        let done = runs.get(&id).map_or(false, |r| r.lock_us != 0 && r.result_us != 0 && r.settle_us != 0);
        if done {
            let r = runs.remove(&id).unwrap();
            finished += 1;
            if finished > cfg.warmup_tasks {
                samples += 1;
                lock_sum += r.lock_us - r.t0;
                result_sum += r.result_us - r.t0;
                settle_sum += r.settle_us - r.t0;
                first_t0 = first_t0.min(r.t0);
                last_settle = last_settle.max(r.settle_us);
            }
            if started < cfg.tasks {
                start(&mut runs, &mut started);
            }
        }
    }
    let avg_ms = |sum: u64| sum as f64 / samples.max(1) as f64 / 1000.0;
    let tput = samples as f64 / ((last_settle.saturating_sub(first_t0)) as f64 / 1e6).max(1e-9);
    cfg.append_summary(
        "clients.csv",
        &format!("{samples},{:.1},{:.1},{:.1},{tput:.2}", avg_ms(lock_sum), avg_ms(result_sum), avg_ms(settle_sum)),
    )?;
    eprintln!("client {pair}: {finished} tasks done");
    Ok(())
}