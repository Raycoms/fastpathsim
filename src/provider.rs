//! Provider (Algorithm "Provider"): forms the LockQC, runs the (simulated) inference, sends the
//! signed result to the client (Option A) or to the validators (Option B), and forms the SettleQC.

use crate::config::Config;
use crate::crypto::{ed_key, ed_sign, Committee, Qc, Votes};
use crate::msg::*;
use crate::net::{self, broadcast, encode, now_us, send, Tx};
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;

enum Ev {
    Net(Msg),
    Inferred(Id),
}

#[derive(Default)]
struct Run {
    task: Option<Task>,
    lock_votes: Votes,
    qc: Option<Qc>,
    lock: Option<LockQc>,
    settle_votes: HashMap<u64, Votes>,
    settled: bool,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let (ev_tx, mut ev_rx) = unbounded_channel::<Ev>();
    let mut validators: Vec<Tx> = vec![];
    for &addr in &cfg.validators {
        let (r, tx) = net::connect(addr, Role::Provider).await;
        let e = ev_tx.clone();
        net::read_loop(r, move |m| {
            let _ = e.send(Ev::Net(m));
        });
        validators.push(tx);
    }
    let (r, client) = net::connect(cfg.client, Role::Provider).await;
    let e = ev_tx.clone();
    net::read_loop(r, move |m| {
        let _ = e.send(Ev::Net(m));
    });
    eprintln!("provider: connected to {} validators and the client", validators.len());

    let committee = Committee::new(cfg.validators.len());
    let sk = ed_key("provider");
    let mut out = std::fs::File::create(cfg.results.join("provider.csv"))?;
    writeln!(out, "id,lockqc_us,proof_us,settle_us")?;
    let mut times: HashMap<Id, (u64, u64)> = HashMap::new();
    let mut runs: HashMap<Id, Run> = (0..cfg.tasks as u64)
        .map(|i| Task::agreed(i, cfg.client_pk, cfg.provider_pk))
        .map(|t| (t.id(), Run { task: Some(t), ..Default::default() }))
        .collect();
    let (y, pi) = (vec![1u8; cfg.y_bytes], vec![2u8; cfg.proof_bytes]);

    while let Some(ev) = ev_rx.recv().await {
        let id = match ev {
            Ev::Net(Msg::LockVote { id, signer, sig }) => {
                let Some(r) = runs.get_mut(&id) else { continue };
                if let Some(qc) = r.lock_votes.add(&committee, &lock_msg(&id), signer, &sig) {
                    r.qc = Some(qc);
                }
                id
            }
            Ev::Inferred(id) => {
                let lock = runs[&id].lock.clone().unwrap();
                let sig = ed_sign(&sk, &proof_msg(&id, &y, &pi));
                let m = Msg::Proof(Proof { lock, y: y.clone(), pi: pi.clone(), sig });
                if cfg.option_b {
                    broadcast(&validators, &m);
                } else {
                    send(&client, &encode(&m));
                }
                times.get_mut(&id).unwrap().1 = now_us();
                continue;
            }
            Ev::Net(Msg::SettleVote { id, value, signer, sig }) => {
                let Some(r) = runs.get_mut(&id) else { continue };
                let Some(lock) = r.lock.clone() else { continue };
                if r.settled || (value != lock.task.amount + G_P && value != lock.task.amount) {
                    continue;
                }
                let votes = r.settle_votes.entry(value).or_default();
                if let Some(qc) = votes.add(&committee, &settle_msg(&id, value), signer, &sig) {
                    r.settled = true;
                    let (lock_us, proof_us) = times[&id];
                    let hex: String = id[..8].iter().map(|b| format!("{b:02x}")).collect();
                    writeln!(out, "{hex},{lock_us},{proof_us},{}", now_us())?;
                    out.flush()?;
                    // Option B needs the forward: validators deliver y once they see the SettleQC.
                    if cfg.forward || cfg.option_b {
                        broadcast(&validators, &Msg::Settled { lock, settle: SettleQc { id, value, qc } });
                    }
                }
                continue;
            }
            _ => continue,
        };
        // Start the inference once the task is negotiated and locked (P-start).
        let r = runs.get_mut(&id).unwrap();
        if let (None, Some(task), Some(qc)) = (&r.lock, &r.task, &r.qc) {
            r.lock = Some(LockQc { task: task.clone(), qc: qc.clone() });
            times.insert(id, (now_us(), 0));
            let e = ev_tx.clone();
            tokio::spawn(async move {
                let _ = e.send(Ev::Inferred(id));
            });
        }
    }
    Ok(())
}
