//! 与引擎侧实现（omni-rt-risk/risk-binary）的互通测试：
//! tests/golden/*.bin 由引擎的 RbpFrame 编码生成（见仓库提交说明），此处用本 crate
//! 的 fin-protoc 生成代码解码并逐字段断言，再重编码要求字节级一致。
//! 任何字段顺序/类型/定长/字节序漂移都会在这里暴露。

use binary_codec::BinaryCodec;
use bytes::{Bytes, BytesMut};
use risk_binary::rbp_binary::{RbpBinary, RbpBinaryBodyEnum};

fn roundtrip(name: &str, raw: &'static [u8]) -> RbpBinary {
    let mut buf = Bytes::from_static(raw);
    let decoded =
        RbpBinary::decode(&mut buf).unwrap_or_else(|| panic!("{name}: 引擎 golden 帧解码失败"));
    assert!(buf.is_empty(), "{name}: 解码后仍有残留字节");

    let mut re = BytesMut::new();
    decoded.encode(&mut re);
    assert_eq!(re.as_ref(), raw, "{name}: 重编码字节不一致");
    decoded
}

#[test]
fn golden_logon() {
    let m = roundtrip("logon", include_bytes!("golden/01_logon.bin"));
    assert_eq!(m.msg_type, 1);
    assert_eq!(m.version, 1);
    assert_eq!(m.msg_seq, 1);
    assert_eq!(m.ts_ns, 1_700_000_000_000_000_001);
    let RbpBinaryBodyEnum::Logon(body) = m.body else {
        panic!("expect Logon")
    };
    assert_eq!(body.gateway_id, "gw-front-01");
    assert_eq!(body.role, 1);
    assert_eq!(body.proto_ver, 1);
    assert_eq!(body.heartbeat_ms, 1000);
    assert_eq!(body.caps, 0b1);
}

#[test]
fn golden_logon_ack() {
    let m = roundtrip("logon_ack", include_bytes!("golden/02_logon_ack.bin"));
    assert_eq!(m.msg_type, 2);
    let RbpBinaryBodyEnum::LogonAck(body) = m.body else {
        panic!("expect LogonAck")
    };
    assert_eq!(body.engine_id, "engine-01");
    assert_eq!(body.session_id, 42);
    assert_eq!(body.accept, 0);
}

#[test]
fn golden_heartbeat_no_checksum_flag() {
    let m = roundtrip("heartbeat", include_bytes!("golden/03_heartbeat.bin"));
    assert_eq!(m.msg_type, 3);
    assert_eq!(m.flags, 1 << 4, "引擎侧 NO_CHECKSUM 标志应原样透传");
    assert_eq!(m.checksum, 0, "NO_CHECKSUM 帧校验和为 0");
    let RbpBinaryBodyEnum::Heartbeat(body) = m.body else {
        panic!("expect Heartbeat")
    };
    assert_eq!(body.last_recv_seq, 99);
}

#[test]
fn golden_session_reject() {
    let m = roundtrip(
        "session_reject",
        include_bytes!("golden/04_session_reject.bin"),
    );
    assert_eq!(m.msg_type, 6);
    let RbpBinaryBodyEnum::SessionReject(body) = m.body else {
        panic!("expect SessionReject")
    };
    assert_eq!(body.err_code, 1);
    assert_eq!(body.text, "version mismatch");
}

#[test]
fn golden_new_order_req() {
    let m = roundtrip(
        "new_order_req",
        include_bytes!("golden/05_new_order_req.bin"),
    );
    assert_eq!(m.msg_type, 16);
    assert_eq!(m.body_len, 123);
    let RbpBinaryBodyEnum::NewOrderReq(body) = m.body else {
        panic!("expect NewOrderReq")
    };
    assert_eq!(body.req_id, 1001);
    assert_eq!(body.channel_id, 1);
    assert_eq!(body.adapter, 1);
    assert_eq!(body.account, "A123");
    assert_eq!(body.account_group, "G1");
    assert_eq!(body.cl_ord_id, "C0001");
    assert_eq!(body.security_id, "600000");
    assert_eq!(body.market, 1);
    assert_eq!(body.side, 1);
    assert_eq!(body.price, 1050);
    assert_eq!(body.order_qty, 100);
    assert_eq!(body.ord_type, 1);
    assert_eq!(body.time_in_force, 0);
    assert_eq!(body.pbu, "P0001");
    assert_eq!(body.transact_time, 1_700_000_000);
    assert_eq!(body.ts_recv_ns, 123_456);
    assert_eq!(body.raw_ref, 7);
}

#[test]
fn golden_cancel_req() {
    let m = roundtrip("cancel_req", include_bytes!("golden/06_cancel_req.bin"));
    assert_eq!(m.msg_type, 17);
    assert_eq!(m.body_len, 88);
    let RbpBinaryBodyEnum::CancelReq(body) = m.body else {
        panic!("expect CancelReq")
    };
    assert_eq!(body.req_id, 1002);
    assert_eq!(body.cl_ord_id, "C0002");
    assert_eq!(body.orig_cl_ord_id, "C0001");
    assert_eq!(body.security_id, "600000");
    assert_eq!(body.side, 1);
    assert_eq!(body.raw_ref, 8);
}

#[test]
fn golden_order_confirm() {
    let m = roundtrip(
        "order_confirm",
        include_bytes!("golden/07_order_confirm.bin"),
    );
    assert_eq!(m.msg_type, 18);
    assert_eq!(m.body_len, 76);
    let RbpBinaryBodyEnum::OrderConfirm(body) = m.body else {
        panic!("expect OrderConfirm")
    };
    assert_eq!(body.req_id, 1001);
    assert_eq!(body.cl_ord_id, "C0001");
    assert_eq!(body.order_id, "O9");
    assert_eq!(body.ord_status, 1);
}

#[test]
fn golden_trade_report() {
    let m = roundtrip("trade_report", include_bytes!("golden/08_trade_report.bin"));
    assert_eq!(m.msg_type, 19);
    assert_eq!(m.body_len, 138);
    let RbpBinaryBodyEnum::TradeReport(body) = m.body else {
        panic!("expect TradeReport")
    };
    assert_eq!(body.exec_id, "E1");
    assert_eq!(body.exec_type, 0);
    assert_eq!(body.ord_status, 3);
    assert_eq!(body.last_px, 1050);
    assert_eq!(body.last_qty, 40);
    assert_eq!(body.cum_qty, 40);
    assert_eq!(body.leaves_qty, 60);
}

#[test]
fn golden_cancel_reject() {
    let m = roundtrip(
        "cancel_reject",
        include_bytes!("golden/09_cancel_reject.bin"),
    );
    assert_eq!(m.msg_type, 20);
    assert_eq!(m.body_len, 109);
    let RbpBinaryBodyEnum::CancelReject(body) = m.body else {
        panic!("expect CancelReject")
    };
    assert_eq!(body.cl_ord_id, "C0002");
    assert_eq!(body.orig_cl_ord_id, "C0001");
    assert_eq!(body.reason_code, 0);
    assert_eq!(body.text, "filled");
}

#[test]
fn golden_order_reject() {
    let m = roundtrip("order_reject", include_bytes!("golden/10_order_reject.bin"));
    assert_eq!(m.msg_type, 21);
    let RbpBinaryBodyEnum::OrderReject(body) = m.body else {
        panic!("expect OrderReject")
    };
    assert_eq!(body.channel_id, 2);
    assert_eq!(body.adapter, 2);
    assert_eq!(body.cl_ord_id, "C0003");
    assert_eq!(body.reason_code, 1);
    assert_eq!(body.text, "no cash");
}

#[test]
fn golden_risk_result() {
    let m = roundtrip("risk_result", include_bytes!("golden/11_risk_result.bin"));
    assert_eq!(m.msg_type, 32);
    assert_eq!(m.body_len, 77);
    let RbpBinaryBodyEnum::RiskResult(body) = m.body else {
        panic!("expect RiskResult")
    };
    assert_eq!(body.req_id, 1001);
    assert_eq!(body.decision, 1);
    assert_eq!(body.code, 1002);
    assert_eq!(body.rule_id, 5);
    assert_eq!(body.ts_recv_ns, 123_456);
    assert_eq!(body.ts_engine_ns, 223_456);
    assert_eq!(body.text, "over limit");
}

#[test]
fn golden_instruction() {
    let m = roundtrip("instruction", include_bytes!("golden/12_instruction.bin"));
    assert_eq!(m.msg_type, 48);
    assert_eq!(m.body_len, 75);
    let RbpBinaryBodyEnum::Instruction(body) = m.body else {
        panic!("expect Instruction")
    };
    assert_eq!(body.instr_id, 55);
    assert_eq!(body.instr_type, 3);
    assert_eq!(body.target_type, 1);
    assert_eq!(body.target, "A123");
    assert_eq!(body.expiry_ns, 0);
    assert_eq!(body.operator, "risk-op");
}

#[test]
fn golden_instr_ack() {
    let m = roundtrip("instr_ack", include_bytes!("golden/13_instr_ack.bin"));
    assert_eq!(m.msg_type, 49);
    assert_eq!(m.body_len, 17);
    let RbpBinaryBodyEnum::InstrAck(body) = m.body else {
        panic!("expect InstrAck")
    };
    assert_eq!(body.instr_id, 55);
    assert_eq!(body.result, 0);
}
