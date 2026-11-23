mod client;
mod config;
mod crypto;
mod msg;
mod net;
mod provider;
mod validator;

fn main() -> anyhow::Result<()> {
    let role = std::env::args().nth(1).unwrap_or_default();
    if role == "bench" {
        let n = std::env::args().nth(2).and_then(|n| n.parse().ok()).unwrap_or(128);
        return bench(n);
    }
    let cfg = config::Config::from_env()?;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(cfg.workers).enable_all().build()?;
    rt.block_on(async move {
        match role.as_str() {
            "validator" => validator::run(cfg).await,
            "client" => client::run(cfg).await,
            "provider" => provider::run(cfg).await,
            _ => anyhow::bail!("usage: fastsim validator|client|provider"),
        }
    })
}

/// CPU cost of the operations a validator performs per task, to size the host.
fn bench(n: usize) -> anyhow::Result<()> {
    use std::time::Instant;
    let c = crypto::Committee::new(n);
    let msg = b"lock-bench";
    let sks: Vec<_> = (0..c.quorum).map(crypto::bls_key).collect();
    let time = |name: &str, reps: u32, f: &mut dyn FnMut()| {
        let t = Instant::now();
        (0..reps).for_each(|_| f());
        println!("{name}: {:.3} ms", t.elapsed().as_secs_f64() * 1e3 / reps as f64);
    };
    time("BLS sign", 100, &mut || drop(crypto::bls_sign(&sks[0], msg)));
    let mut votes = crypto::Votes::default();
    let sigs: Vec<_> = sks.iter().map(|sk| crypto::bls_sign(sk, msg)).collect();
    let q = c.quorum;
    time("check one arriving vote", 1, &mut || {
        sigs[..q - 1].iter().enumerate().for_each(|(i, s)| assert!(votes.add(&c, msg, i as u16, s).is_none()));
    });
    println!("  (per vote, divide by {})", q - 1);
    let mut qc = None;
    time(&format!("last vote: aggregate {q} and verify once"), 1, &mut || qc = votes.add(&c, msg, (q - 1) as u16, &sigs[q - 1]));
    let qc = qc.expect("no QC");
    time(&format!("verify QC (n = {n})"), 100, &mut || assert!(c.verify_qc(msg, &qc)));
    let ed = crypto::ed_key("bench");
    let (pk, sig) = (ed.verifying_key().to_bytes(), crypto::ed_sign(&ed, msg));
    time("Ed25519 verify", 1000, &mut || assert!(crypto::ed_verify(&pk, msg, &sig)));
    Ok(())
}
