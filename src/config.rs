//! Configuration from environment variables and a peers file with lines "<role> <ip:port>".

use crate::crypto::ed_key;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone)]
pub struct Config {
    pub id: usize,
    pub validators: Vec<SocketAddr>,
    pub client: SocketAddr,
    pub client_pk: [u8; 32],
    pub provider_pk: [u8; 32],
    /// Option B (validators verify) instead of Option A (client releases).
    pub option_b: bool,
    pub tasks: usize,
    pub concurrency: usize,
    pub warmup_s: u64,
    pub y_bytes: usize,
    pub proof_bytes: usize,
    /// Forward SettleQCs to the validators (off the latency path, but it loads them).
    pub forward: bool,
    pub results: PathBuf,
    pub workers: usize,
}

fn env<T: FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let peers = std::fs::read_to_string(env("PEERS", "/config/peers.txt".to_string()))?;
        let (mut validators, mut client) = (vec![], None);
        for line in peers.lines().filter(|l| !l.trim().is_empty()) {
            let mut it = line.split_whitespace();
            let (role, addr): (&str, SocketAddr) = (it.next().unwrap(), it.next().unwrap().parse()?);
            match role {
                "validator" => validators.push(addr),
                "client" => client = Some(addr),
                "provider" => {} // the provider only dials out
                _ => anyhow::bail!("unknown role {role}"),
            }
        }
        Ok(Self {
            id: env("ID", 0),
            validators,
            client: client.expect("no client in peers file"),
            client_pk: ed_key("client").verifying_key().to_bytes(),
            provider_pk: ed_key("provider").verifying_key().to_bytes(),
            option_b: env("OPTION", "A".to_string()).eq_ignore_ascii_case("B"),
            tasks: env("TASKS", 200),
            concurrency: env("CONCURRENCY", 1),
            warmup_s: env("WARMUP_S", 3),
            y_bytes: env("Y_BYTES", 4096),
            proof_bytes: env("PROOF_BYTES", 8192),
            forward: env("FORWARD", 1) == 1,
            results: PathBuf::from(env("RESULTS", "/results".to_string())),
            workers: env("WORKERS", 2),
        })
    }
}
