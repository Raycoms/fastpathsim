use crate::config::Config;
use crate::crypto::{ed_key, ed_sign, ed_verify, Committee, Votes};
use crate::msg::*;
use crate::net::{self, broadcast, encode, now_us, send, Tx};
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

enum Ev {
    Net(Msg),
    Verified(Id),
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
    let listener = TcpListener::bind(("0.0.0.0", cfg.client.port())).await?;

    let mut validators: Vec<Tx> = vec![];
    for &addr in &cfg.validators {
        let (r, tx) = net::connect(addr, Role::Client).await;
        net::read_loop(r, feed(ev_tx.clone()));
        validators.push(tx);
    }
    // The provider connects to us once it is connected to all validators.
    let (stream, _) = listener.accept().await?;
    let (mut r, _provider) = net::split(stream);

    anyhow::ensure!(matches!(net::read_msg(&mut r).await?, Msg::Hello(Role::Provider)));
    net::read_loop(r, feed(ev_tx.clone()));
    eprintln!("client: connected to {} validators and the provider", validators.len());
    tokio::time::sleep(Duration::from_secs(cfg.warmup_s)).await;

    let committee = Committee::new(cfg.validators.len());
    let sk = ed_key("client");
    let mut out = std::fs::File::create(cfg.results.join("client.csv"))?;
    writeln!(out, "id,t0_us,lock_us,result_us,settle_us")?;

    let mut runs: HashMap<Id, Run> = HashMap::new();
    let (mut started, mut finished) = (0usize, 0usize);
    let start = |runs: &mut HashMap<Id, Run>, started: &mut usize| {
        let task = Task::agreed(*started as u64, cfg.client_pk, cfg.provider_pk);
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
            _ => anyhow::bail!("client: no progress for 60 s, {finished} of {} tasks done", cfg.tasks),
        };
        let id = match ev {
            Ev::Net(Msg::LockVote { id, signer, sig }) => {
                let Some(r) = runs.get_mut(&id) else { continue };
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
                // VerifyProof at the client, modeled as a delay.
                let e = ev_tx.clone();
                tokio::spawn(async move {
                    let _ = e.send(Ev::Verified(id));
                });
                id
            }
            Ev::Verified(id) => {
                let Some(r) = runs.get(&id) else { continue };
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
        let done = runs.get(&id).map_or(false, |r| r.settle_us != 0 && r.result_us != 0);
        if done {
            let r = runs.remove(&id).unwrap();
            let hex: String = id[..8].iter().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "{hex},{},{},{},{}", r.t0, r.lock_us, r.result_us, r.settle_us)?;
            finished += 1;
            if started < cfg.tasks {
                start(&mut runs, &mut started);
            }
        }
    }
    out.flush()?;
    eprintln!("client: {finished} tasks done");
    Ok(())
}
