//! External STUN availability checks for the deployed edge endpoint.
//!
//! These tests require public DNS/network access and a live deployment, so they
//! are ignored by default.

use std::sync::Arc;
use std::time::Duration;

use dtls::config::Config as DtlsConfig;
use dtls::conn::DTLSConn;
use miuturn::ensure_rustls_crypto_provider;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{Instant, timeout};
use webrtc_util::conn::Conn;

const DEFAULT_EDGE_STUN_ADDR: &str = "edge0.cn-0.dev.novo-one.com:5349";
const TRANSACTION_ID: [u8; 12] = [
    0x65, 0x64, 0x67, 0x65, 0x30, 0x2d, 0x73, 0x74, 0x75, 0x6e, 0x01, 0x02,
];
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const RECV_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

fn edge_stun_addr() -> String {
    std::env::var("EDGE_STUN_ADDR").unwrap_or_else(|_| DEFAULT_EDGE_STUN_ADDR.to_string())
}

fn stun_binding_request() -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0x2112A442u32.to_be_bytes());
    msg.extend_from_slice(&TRANSACTION_ID);
    msg
}

fn response_has_xor_mapped_address(buf: &[u8]) -> bool {
    let message_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = 20usize;
    let end = 20 + message_len;

    while offset + 4 <= end && offset + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > end || value_end > buf.len() {
            return false;
        }

        if attr_type == 0x0020 {
            return attr_len >= 8;
        }

        let padding = (4 - (attr_len % 4)) % 4;
        offset = value_end + padding;
    }

    false
}

#[tokio::test]
#[ignore = "requires public DNS/network access and the deployed edge STUN endpoint"]
async fn edge0_cn0_dev_stun_over_dtls_is_available() {
    ensure_rustls_crypto_provider();

    let configured_addr = edge_stun_addr();
    let server_addr = lookup_host(&configured_addr)
        .await
        .unwrap_or_else(|err| panic!("resolve {configured_addr}: {err}"))
        .next()
        .unwrap_or_else(|| panic!("no socket addresses resolved for {configured_addr}"));
    println!("probing STUN over DTLS at {configured_addr} ({server_addr})");

    let udp = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("bind local UDP socket"),
    );
    udp.connect(server_addr)
        .await
        .unwrap_or_else(|err| panic!("connect UDP socket to {server_addr}: {err}"));

    let conn = DTLSConn::new(
        udp,
        DtlsConfig {
            insecure_skip_verify: true,
            ..Default::default()
        },
        true,
        None,
    )
    .await
    .unwrap_or_else(|err| panic!("establish DTLS session to {server_addr}: {err}"));

    let request = stun_binding_request();
    let mut buf = vec![0u8; 1500];
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let mut attempts = 0usize;
    let len = loop {
        attempts += 1;
        conn.send(&request)
            .await
            .unwrap_or_else(|err| panic!("send STUN Binding Request to {server_addr}: {err}"));

        match timeout(RECV_ATTEMPT_TIMEOUT, conn.recv(&mut buf)).await {
            Ok(Ok(len)) => break len,
            Ok(Err(err)) => panic!("receive STUN response from {server_addr}: {err}"),
            Err(_) if Instant::now() < deadline => continue,
            Err(_) => {
                panic!(
                    "timeout waiting for STUN response from {server_addr} after {attempts} attempts"
                )
            }
        }
    };
    println!("received {len} byte STUN response from {server_addr} after {attempts} attempt(s)");

    let resp = &buf[..len];
    assert!(resp.len() >= 20, "response too short: {} bytes", resp.len());
    assert_eq!(
        u16::from_be_bytes([resp[0], resp[1]]),
        0x0101,
        "expected STUN Binding Success Response"
    );
    assert_eq!(
        &resp[4..8],
        &0x2112A442u32.to_be_bytes(),
        "invalid STUN magic cookie"
    );
    assert_eq!(
        &resp[8..20],
        &TRANSACTION_ID,
        "response transaction id does not match request"
    );
    assert!(
        response_has_xor_mapped_address(resp),
        "response missing XOR-MAPPED-ADDRESS"
    );
}
