//! Configuration from environment variables and a peers file with lines "<role> <ip:port>". The
//! i-th client and the i-th provider form pair i.

use crate::crypto::ed_key;
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Key of the client or provider of a pair.
pub fn pair_key(role: &str, pair: usize) -> SigningKey {
    ed_key(&format!("{role}-{pair}"))
}

#[derive(Clone)]
pub struct Config {
    pub id: usize,
    pub validators: Vec<SocketAddr>,
    /// Client addresses, by pair.
    pub clients: Vec<SocketAddr>,
    /// This process's pair (clients and providers only).
    pub pair: usize,
    pub client_pks: Vec<[u8; 32]>,
    pub provider_pks: Vec<[u8; 32]>,
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
    /// Label written into the summary lines, e.g. the run's name.
    pub run: String,
    /// Tasks per client left out of the averages.
    pub warmup_tasks: usize,
    pub workers: usize,
}

fn env<T: FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

impl Config {
    /// The run's settings, the first columns of every summary line.
    pub fn summary_prefix(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{}",
            self.run,
            self.pair,
            self.validators.len(),
            if self.option_b { "B" } else { "A" },
            self.clients.len(),
            self.concurrency,
            self.tasks,
            self.proof_bytes
        )
    }

    /// Appends one line to a summary file shared by all containers. A single small append is atomic.
    pub fn append_summary(&self, file: &str, line: &str) -> anyhow::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.results.join(file))?;
        f.write_all(format!("{},{line}\n", self.summary_prefix()).as_bytes())?;
        Ok(())
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let peers = std::fs::read_to_string(env("PEERS", "/config/peers.txt".to_string()))?;
        let (mut validators, mut clients) = (vec![], vec![]);
        for line in peers.lines().filter(|l| !l.trim().is_empty()) {
            let mut it = line.split_whitespace();
            let (role, addr): (&str, SocketAddr) = (it.next().unwrap(), it.next().unwrap().parse()?);
            match role {
                "validator" => validators.push(addr),
                "client" => clients.push(addr),
                "provider" => {} // the provider only dials out
                _ => anyhow::bail!("unknown role {role}"),
            }
        }
        let pks = |role: &str| (0..clients.len()).map(|i| pair_key(role, i).verifying_key().to_bytes()).collect();
        Ok(Self {
            id: env("ID", 0),
            validators,
            pair: env("PAIR", 0),
            client_pks: pks("client"),
            provider_pks: pks("provider"),
            clients,
            option_b: env("OPTION", "A".to_string()).eq_ignore_ascii_case("B"),
            tasks: env("TASKS", 200),
            concurrency: env("CONCURRENCY", 1),
            warmup_s: env("WARMUP_S", 3),
            y_bytes: env("Y_BYTES", 4096),
            proof_bytes: env("PROOF_BYTES", 8192),
            forward: env("FORWARD", 1) == 1,
            results: PathBuf::from(env("RESULTS", "/results".to_string())),
            run: env("RUN", String::new()),
            warmup_tasks: env("WARMUP_TASKS", 5),
            workers: env("WORKERS", 2),
        })
    }
}