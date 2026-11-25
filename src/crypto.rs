//! Signatures. Validators sign votes with BLS12-381 (min_sig, as Sui), so a certificate is one
//! aggregate signature plus the signer list. Clients and providers sign with Ed25519.

use blst::min_sig::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Deterministic keys, so every process knows every public key without a setup phase.
pub fn bls_key(i: usize) -> SecretKey {
    SecretKey::key_gen(&sha256(format!("validator-{i}").as_bytes()), &[]).unwrap()
}

pub fn ed_key(name: &str) -> SigningKey {
    SigningKey::from_bytes(&sha256(name.as_bytes()))
}

pub fn bls_sign(sk: &SecretKey, msg: &[u8]) -> Vec<u8> {
    sk.sign(msg, DST, &[]).to_bytes().to_vec()
}

pub fn ed_sign(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    sk.sign(msg).to_bytes().to_vec()
}

pub fn ed_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (VerifyingKey::from_bytes(pk), sig.try_into()) else { return false };
    pk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
}

/// A quorum certificate: an aggregate BLS signature by the listed validators.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Qc {
    pub signers: Vec<u16>,
    pub sig: Vec<u8>,
}

pub struct Committee {
    pub pks: Vec<PublicKey>,
    pub quorum: usize,
}

impl Committee {
    pub fn new(n: usize) -> Self {
        let f = (n - 1) / 3;
        // n - f guarantees that two quorums share a correct validator for any n, and equals 2f+1 for n = 3f+1.
        Self { pks: (0..n).map(|i| bls_key(i).sk_to_pk()).collect(), quorum: n - f }
    }

    fn verify_agg(&self, signers: &[u16], msg: &[u8], sig: &Signature) -> bool {
        let pks: Vec<&PublicKey> = signers.iter().map(|&i| &self.pks[i as usize]).collect();
        let Ok(apk) = AggregatePublicKey::aggregate(&pks, false) else { return false };
        sig.verify(true, msg, DST, &[], &apk.to_public_key(), false) == BLST_ERROR::BLST_SUCCESS
    }

    /// `ValidQC`: at least a quorum of distinct, known signers and a valid aggregate signature.
    pub fn verify_qc(&self, msg: &[u8], qc: &Qc) -> bool {
        let sorted = qc.signers.windows(2).all(|w| w[0] < w[1]);
        let known = qc.signers.last().map_or(false, |&i| (i as usize) < self.pks.len());
        let Ok(sig) = Signature::from_bytes(&qc.sig) else { return false };
        sorted && known && qc.signers.len() >= self.quorum && self.verify_agg(&qc.signers, msg, &sig)
    }
}

/// Collects votes on one message until they form a certificate. It aggregates the first quorum and
/// verifies the aggregate once. Only if that fails does it check the votes one by one.
#[derive(Default)]
pub struct Votes {
    sigs: BTreeMap<u16, Signature>,
    pub done: bool,
}

impl Votes {
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn add(&mut self, c: &Committee, msg: &[u8], signer: u16, sig: &[u8]) -> Option<Qc> {
        if self.done || signer as usize >= c.pks.len() {
            return None;
        }
        // Decompress and check the subgroup on arrival, so the last vote only adds points.
        let Ok(sig) = Signature::sig_validate(sig, true) else { return None };
        self.sigs.insert(signer, sig);
        if self.sigs.len() < c.quorum {
            return None;
        }
        let signers: Vec<u16> = self.sigs.keys().copied().collect();
        let sigs: Vec<&Signature> = self.sigs.values().collect();
        let agg = AggregateSignature::aggregate(&sigs, false).ok()?.to_signature();
        if !c.verify_agg(&signers, msg, &agg) {
            // Some vote is bad: keep only the valid ones and wait for more.
            self.sigs.retain(|&i, s| s.verify(true, msg, DST, &[], &c.pks[i as usize], false) == BLST_ERROR::BLST_SUCCESS);
            return None;
        }
        self.done = true;
        Some(Qc { signers, sig: agg.to_bytes().to_vec() })
    }
}
