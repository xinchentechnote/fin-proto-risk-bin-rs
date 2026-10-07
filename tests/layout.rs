//! 线格式布局门禁：各消息帧体字节数必须与《03-风控二进制协议RBP设计》§4 字段表一致，
//! 帧头恒定 32B。任何一侧变更导致字节数漂移都会在这里失败。

use binary_codec::BinaryCodec;
use bytes::BytesMut;
use risk_binary::rbp_binary::{RbpBinary, RbpBinaryBodyEnum};
use risk_binary::{
    cancel_reject::CancelReject, cancel_req::CancelReq, instr_ack::InstrAck,
    instruction::Instruction, new_order_req::NewOrderReq, order_confirm::OrderConfirm,
    order_reject::OrderReject, risk_result::RiskResult, trade_report::TradeReport,
};

fn assert_body_len<M: BinaryCodec>(expect_len: usize, msg: &M, name: &str) {
    let mut buf = BytesMut::new();
    msg.encode(&mut buf);
    assert_eq!(buf.len(), expect_len, "{name} 帧体长度漂移");
}

fn envelope_len(body: RbpBinaryBodyEnum, msg_type: u32) -> usize {
    let m = RbpBinary {
        msg_type,
        version: 1,
        flags: 0,
        msg_seq: 1,
        ts_ns: 0,
        body_len: 0,
        checksum: 0,
        body,
    };
    let mut buf = BytesMut::new();
    m.encode(&mut buf);
    buf.len()
}

#[test]
fn body_sizes_match_design_doc() {
    assert_body_len(
        123,
        &NewOrderReq {
            req_id: 1,
            channel_id: 1,
            adapter: 1,
            account: "a".into(),
            account_group: "g".into(),
            cl_ord_id: "c".into(),
            security_id: "600000".into(),
            market: 1,
            side: 1,
            price: 1,
            order_qty: 1,
            ord_type: 1,
            time_in_force: 0,
            pbu: "p".into(),
            transact_time: 0,
            ts_recv_ns: 0,
            raw_ref: 0,
        },
        "NewOrderReq",
    );
    assert_body_len(
        88,
        &CancelReq {
            req_id: 1,
            channel_id: 1,
            adapter: 1,
            account: "a".into(),
            cl_ord_id: "c".into(),
            orig_cl_ord_id: "o".into(),
            security_id: "600000".into(),
            side: 1,
            ts_recv_ns: 0,
            raw_ref: 0,
        },
        "CancelReq",
    );
    assert_body_len(
        77,
        &RiskResult {
            req_id: 1,
            decision: 0,
            code: 0,
            rule_id: 0,
            ts_recv_ns: 0,
            ts_engine_ns: 0,
            text: "t".into(),
        },
        "RiskResult",
    );
    assert_body_len(
        76,
        &OrderConfirm {
            req_id: 0,
            channel_id: 1,
            adapter: 1,
            account: "a".into(),
            cl_ord_id: "c".into(),
            order_id: "o".into(),
            ord_status: 1,
            ts_ns: 0,
            raw_ref: 0,
        },
        "OrderConfirm",
    );
    assert_body_len(
        138,
        &TradeReport {
            req_id: 0,
            channel_id: 1,
            adapter: 1,
            account: "a".into(),
            cl_ord_id: "c".into(),
            order_id: "o".into(),
            exec_id: "e".into(),
            exec_type: 0,
            ord_status: 2,
            security_id: "600000".into(),
            side: 1,
            last_px: 1,
            last_qty: 1,
            cum_qty: 1,
            leaves_qty: 0,
            ts_ns: 0,
            raw_ref: 0,
        },
        "TradeReport",
    );
    assert_body_len(
        109,
        &CancelReject {
            req_id: 0,
            channel_id: 1,
            adapter: 1,
            account: "a".into(),
            cl_ord_id: "c".into(),
            orig_cl_ord_id: "o".into(),
            reason_code: 0,
            text: "t".into(),
            ts_ns: 0,
            raw_ref: 0,
        },
        "CancelReject",
    );
    assert_body_len(
        109,
        &OrderReject {
            req_id: 0,
            channel_id: 1,
            adapter: 1,
            account: "a".into(),
            cl_ord_id: "c".into(),
            orig_cl_ord_id: "o".into(),
            reason_code: 0,
            text: "t".into(),
            ts_ns: 0,
            raw_ref: 0,
        },
        "OrderReject",
    );
    assert_body_len(
        75,
        &Instruction {
            instr_id: 1,
            instr_type: 1,
            target_type: 1,
            target: "a".into(),
            expiry_ns: 0,
            operator: "op".into(),
            ts_ns: 0,
        },
        "Instruction",
    );
    assert_body_len(
        17,
        &InstrAck {
            instr_id: 1,
            result: 0,
            ts_ns: 0,
        },
        "InstrAck",
    );
}

#[test]
fn envelope_is_32b_header_plus_body() {
    let instr_ack = RbpBinaryBodyEnum::InstrAck(InstrAck {
        instr_id: 1,
        result: 0,
        ts_ns: 0,
    });
    let new_order_req = RbpBinaryBodyEnum::NewOrderReq(NewOrderReq {
        req_id: 1,
        channel_id: 1,
        adapter: 1,
        account: "a".into(),
        account_group: "g".into(),
        cl_ord_id: "c".into(),
        security_id: "600000".into(),
        market: 1,
        side: 1,
        price: 1,
        order_qty: 1,
        ord_type: 1,
        time_in_force: 0,
        pbu: "p".into(),
        transact_time: 0,
        ts_recv_ns: 0,
        raw_ref: 0,
    });
    assert_eq!(envelope_len(instr_ack, 49), 32 + 17);
    assert_eq!(envelope_len(new_order_req, 16), 32 + 123);
}
