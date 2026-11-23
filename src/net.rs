//! Length-prefixed bincode frames over persistent TCP connections. Each connection has one writer
//! task that batches queued frames into a single flush. A broadcast frame is encoded once and shared.

use crate::msg::{Msg, Role};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub type Tx = UnboundedSender<Bytes>;

const MAX_FRAME: usize = 256 << 20;

pub fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

pub fn encode(m: &Msg) -> Bytes {
    let body = bincode::serialize(m).unwrap();
    let mut b = BytesMut::with_capacity(4 + body.len());
    b.put_u32(body.len() as u32);
    b.extend_from_slice(&body);
    b.freeze()
}

pub fn send(tx: &Tx, frame: &Bytes) {
    let _ = tx.send(frame.clone());
}

pub fn broadcast(txs: &[Tx], m: &Msg) {
    let frame = encode(m);
    txs.iter().for_each(|tx| send(tx, &frame));
}

async fn write_loop(w: OwnedWriteHalf, mut rx: UnboundedReceiver<Bytes>) -> anyhow::Result<()> {
    let mut w = BufWriter::with_capacity(1 << 16, w);
    while let Some(f) = rx.recv().await {
        w.write_all(&f).await?;
        while let Ok(f) = rx.try_recv() {
            w.write_all(&f).await?;
        }
        w.flush().await?;
    }
    Ok(())
}

pub async fn read_msg(r: &mut OwnedReadHalf) -> anyhow::Result<Msg> {
    let len = r.read_u32().await? as usize;
    anyhow::ensure!(len <= MAX_FRAME, "frame too large");
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

/// Starts the writer task and returns the reader half and the sender for outgoing frames.
pub fn split(stream: TcpStream) -> (OwnedReadHalf, Tx) {
    stream.set_nodelay(true).unwrap();
    let (r, w) = stream.into_split();
    let (tx, rx) = unbounded_channel();
    tokio::spawn(write_loop(w, rx));
    (r, tx)
}

/// Feeds every message of a connection to `f` until the connection closes.
pub fn read_loop(mut r: OwnedReadHalf, f: impl Fn(Msg) + Send + 'static) {
    tokio::spawn(async move {
        while let Ok(m) = read_msg(&mut r).await {
            f(m);
        }
    });
}

/// Connects (retrying until the peer is up) and introduces ourselves.
pub async fn connect(addr: SocketAddr, role: Role) -> (OwnedReadHalf, Tx) {
    let stream = loop {
        match TcpStream::connect(addr).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    };
    let (r, tx) = split(stream);
    send(&tx, &encode(&Msg::Hello(role)));
    (r, tx)
}
