//! Messages and the byte strings that parties sign.

use crate::crypto::{sha256, Qc};
use serde::{Deserialize, Serialize};

pub type Id = [u8; 32];

/// Fees locked on top of the payment (Table "shares"): provider bonus g_p and client deposit g_c.
pub const G_P: u64 = 1;
pub const G_C: u64 = 1;
/// Every genesis coin is owned by the client and holds this value.
pub const COIN_VALUE: u64 = 1000;

/// tau = <C(q), c, p, a, t, O>
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Task {
    pub commit: [u8; 32],
    pub client: [u8; 32],
    pub provider: [u8; 32],
    pub amount: u64,
    pub deadline_ms: u64,
    pub coins: Vec<u64>,
}

impl Task {
    pub fn agreed(i: u64, client: [u8; 32], provider: [u8; 32]) -> Self {
        Task {
            commit: sha256(format!("query-{i}").as_bytes()),
            client,
            provider,
            amount: 100,
            deadline_ms: u64::MAX,
            coins: vec![i],
        }
    }

    pub fn id(&self) -> Id {
        sha256(&bincode::serialize(self).unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LockQc {
    pub task: Task,
    pub qc: Qc,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SettleQc {
    pub id: Id,
    pub value: u64,
    pub qc: Qc,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proof {
    pub lock: LockQc,
    pub y: Vec<u8>,
    pub pi: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum Role {
    Client,
    Provider,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Msg {
    Hello(Role),
    /// Client to validators.
    Lock { task: Task, sig: Vec<u8> },
    /// Validator to client and provider.
    LockVote { id: Id, signer: u16, sig: Vec<u8> },
    /// Option A: the LockQC signed by the client, client to validators.
    Release { lock: LockQc, sig: Vec<u8> },
    /// Signed result: provider to client (Option A) or to validators (Option B).
    Proof(Proof),
    /// Validator to client and provider.
    SettleVote { id: Id, value: u64, signer: u16, sig: Vec<u8> },
    /// Forwarded certificate, to validators.
    Settled { lock: LockQc, settle: SettleQc },
    /// Option B: the withheld result, validator to client.
    Result { id: Id, y: Vec<u8> },
}

pub fn lock_msg(id: &Id) -> Vec<u8> {
    [b"lock".as_slice(), id].concat()
}

pub fn release_msg(id: &Id) -> Vec<u8> {
    [b"release".as_slice(), id].concat()
}

pub fn settle_msg(id: &Id, value: u64) -> Vec<u8> {
    [b"settle".as_slice(), id, &value.to_le_bytes()].concat()
}

/// Hashing y and pi is part of the cost of checking the provider's signature on a large proof.
pub fn proof_msg(id: &Id, y: &[u8], pi: &[u8]) -> Vec<u8> {
    [b"proof".as_slice(), id, &sha256(y), &sha256(pi)].concat()
}
