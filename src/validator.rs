//! Validator (Algorithm "Validator", fast path only). The consensus unlock and slashing are not on
//! the latency path and are left out.

use crate::config::Config;
use crate::crypto::{bls_key, bls_sign, ed_verify, Committee};
use crate::msg::*;
use crate::net::{self, encode, send, Tx};
use blst::min_sig::SecretKey;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Active,
    Voted,
    Released,
    Settled,
}

struct Escrow {
    status: Status,
    /// The LockQC was verified once, so later messages with it skip the pairing check.
    qc_ok: bool,
    /// Option B justification: the result, withheld until a SettleQC exists.
    y: Option<Vec<u8>>,
}

#[derive(Default)]
struct State {
    escrows: HashMap<Id, Escrow>,
    locked: HashSet<u64>,
}

pub struct Validator {
    cfg: Config,
    me: u16,
    sk: SecretKey,
    committee: Committee,
    state: Mutex<State>,
    /// Connections to clients and providers, by pair.
    clients: Mutex<HashMap<u16, Tx>>,
    providers: Mutex<HashMap<u16, Tx>>,
}

impl Validator {
    fn to_pair(&self, pair: u16, m: &Msg) {
        let frame = encode(m);
        for peers in [&self.clients, &self.providers] {
            if let Some(tx) = peers.lock().unwrap().get(&pair) {
                send(tx, &frame);
            }
        }
    }

    fn new_escrow() -> Escrow {
        Escrow { status: Status::Active, qc_ok: false, y: None }
    }

    /// V-lockcheck: the client owns the coins, none is locked, and they cover a + g_p + g_c.
    fn coins_ok(&self, st: &State, t: &Task) -> bool {
        !t.coins.is_empty()
            && self.cfg.client_pks.get(t.pair()) == Some(&t.client)
            && t.coins.iter().all(|o| (o >> 32) as usize == t.pair())
            && t.coins.iter().all(|o| !st.locked.contains(o))
            && t.coins.len() as u64 * COIN_VALUE >= t.amount + G_P + G_C
    }

    /// ValidQC(LockQC), cached per escrow. A valid LockQC also installs a missed escrow (V-installlock).
    fn lock_ok(&self, id: &Id, lock: &LockQc) -> bool {
        if self.state.lock().unwrap().escrows.get(id).map_or(false, |e| e.qc_ok) {
            return true;
        }
        if !self.committee.verify_qc(&lock_msg(id), &lock.qc) {
            return false;
        }
        self.state.lock().unwrap().escrows.entry(*id).or_insert_with(Self::new_escrow).qc_ok = true;
        true
    }

    fn on_lock(&self, task: Task, sig: Vec<u8>) {
        let id = task.id();
        if !ed_verify(&task.client, &lock_msg(&id), &sig) {
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            if st.escrows.contains_key(&id) || !self.coins_ok(&st, &task) {
                return;
            }
            st.escrows.insert(id, Self::new_escrow());
            st.locked.extend(task.coins.iter().copied());
        }
        let sig = bls_sign(&self.sk, &lock_msg(&id));
        self.to_pair(task.pair() as u16, &Msg::LockVote { id, signer: self.me, sig });
    }

    /// Option A: a LockQC signed by the client releases a + g_p.
    fn on_release(&self, lock: LockQc, sig: Vec<u8>) {
        let id = lock.task.id();
        if !ed_verify(&lock.task.client, &release_msg(&id), &sig) || !self.lock_ok(&id, &lock) {
            return;
        }
        self.vote_settle(&lock.task, lock.task.amount + G_P, None);
    }

    /// Option B: check the provider's signed result, then vote for a. VerifyProof is not emulated.
    fn on_proof(&self, p: Proof) {
        let t = &p.lock.task;
        let id = t.id();
        // stake[p] != bottom: the pair's provider is the staked one.
        let ok = self.cfg.provider_pks.get(t.pair()) == Some(&t.provider)
            && ed_verify(&t.provider, &proof_msg(&id, &p.y, &p.pi), &p.sig)
            && net::now_us() / 1000 <= t.deadline_ms
            && self.lock_ok(&id, &p.lock);
        if ok {
            self.vote_settle(t, t.amount, Some(p.y));
        }
    }

    fn vote_settle(&self, t: &Task, value: u64, y: Option<Vec<u8>>) {
        let id = &t.id();
        {
            let mut st = self.state.lock().unwrap();
            let e = st.escrows.entry(*id).or_insert_with(Self::new_escrow);
            if e.status != Status::Active {
                return;
            }
            e.status = Status::Voted;
            e.y = y;
        }
        let sig = bls_sign(&self.sk, &settle_msg(id, value));
        self.to_pair(t.pair() as u16, &Msg::SettleVote { id: *id, value, signer: self.me, sig });
    }

    fn on_settled(&self, lock: LockQc, s: SettleQc) {
        let t = &lock.task;
        let id = t.id();
        let ok = s.id == id
            && (s.value == t.amount + G_P || s.value == t.amount)
            && self.lock_ok(&id, &lock)
            && self.committee.verify_qc(&settle_msg(&id, s.value), &s.qc);
        if !ok {
            return;
        }
        let y = {
            let mut st = self.state.lock().unwrap();
            let e = st.escrows.entry(id).or_insert_with(Self::new_escrow);
            if matches!(e.status, Status::Released | Status::Settled) {
                return;
            }
            e.status = if s.value == t.amount + G_P { Status::Released } else { Status::Settled };
            e.y.take()
        };
        if let Some(y) = y {
            if let Some(tx) = self.clients.lock().unwrap().get(&(t.pair() as u16)) {
                send(tx, &encode(&Msg::Result { id, y }));
            }
        }
    }

    fn handle(self: &Arc<Self>, m: Msg) {
        match m {
            Msg::Lock { task, sig } => self.on_lock(task, sig),
            Msg::Release { lock, sig } => self.on_release(lock, sig),
            Msg::Proof(p) => self.on_proof(p),
            Msg::Settled { lock, settle } => self.on_settled(lock, settle),
            _ => {}
        }
    }
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let me = cfg.id;
    let listener = TcpListener::bind(("0.0.0.0", cfg.validators[me].port())).await?;
    let v = Arc::new(Validator {
        me: me as u16,
        sk: bls_key(me),
        committee: Committee::new(cfg.validators.len()),
        cfg,
        state: Mutex::default(),
        clients: Mutex::default(),
        providers: Mutex::default(),
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let v = v.clone();
        tokio::spawn(async move {
            let (mut r, tx) = net::split(stream);
            let Ok(Msg::Hello(role, pair)) = net::read_msg(&mut r).await else { return };
            let peers = if role == Role::Client { &v.clients } else { &v.providers };
            peers.lock().unwrap().insert(pair, tx);
            net::read_loop(r, move |m| v.handle(m));
        });
    }
}