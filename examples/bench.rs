//! Encode/decode benchmarks for the risk (RBP) binary library, mirroring
//! bench/bench.zig in fin-proto-risk-bin-zig: same methodology (10k warmup
//! iterations, then 10 batches of 100k operations, fastest batch reported),
//! so the numbers are directly comparable.
//!
//! Output is one TSV line per case on stdout:
//!   lib \t lang \t op \t ns_per_op \t frame_bytes
//!
//! Run with: cargo run --release --example bench

use std::hint::black_box;
use std::time::Instant;

use binary_codec::BinaryCodec;
use bytes::{Bytes, BytesMut};
use risk_binary::new_order_req::NewOrderReq;

const LIB: &str = "risk";
const LANG: &str = "rust";
const ITERS: usize = 100_000;
const BATCHES: usize = 10;
const WARMUP: usize = 10_000;

fn msg() -> NewOrderReq {
    NewOrderReq {
        req_id: 1001,
        channel_id: 1,
        adapter: 1,
        account: "A123".to_string(),
        account_group: "G1".to_string(),
        cl_ord_id: "C0001".to_string(),
        security_id: "600000".to_string(),
        market: 1,
        side: 1,
        price: 1050,
        order_qty: 100,
        ord_type: 1,
        time_in_force: 0,
        pbu: "P0001".to_string(),
        transact_time: 1_700_000_000,
        ts_recv_ns: 123_456,
        raw_ref: 7,
    }
}

fn main() {
    // --- encode -------------------------------------------------------------
    let msg = msg();
    let mut buf = BytesMut::with_capacity(1024);
    for _ in 0..WARMUP {
        buf.clear();
        msg.encode(&mut buf);
    }
    let frame_bytes = buf.len();
    let mut best: u128 = u128::MAX;
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..ITERS {
            buf.clear();
            msg.encode(&mut buf);
        }
        best = best.min(start.elapsed().as_nanos());
    }
    black_box(&buf);
    println!(
        "{}\t{}\tencode\t{:.1}\t{}",
        LIB,
        LANG,
        best as f64 / ITERS as f64,
        frame_bytes
    );

    // --- decode -------------------------------------------------------------
    let raw: &'static [u8] = Box::leak(buf.to_vec().into_boxed_slice());
    for _ in 0..WARMUP {
        let mut b = Bytes::from_static(raw);
        let m = NewOrderReq::decode(&mut b).unwrap();
        black_box(m);
    }
    let mut best: u128 = u128::MAX;
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..ITERS {
            let mut b = Bytes::from_static(raw);
            let m = NewOrderReq::decode(&mut b).unwrap();
            black_box(m);
        }
        best = best.min(start.elapsed().as_nanos());
    }
    println!(
        "{}\t{}\tdecode\t{:.1}\t{}",
        LIB,
        LANG,
        best as f64 / ITERS as f64,
        raw.len()
    );
}
