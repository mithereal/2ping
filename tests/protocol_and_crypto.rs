use std::time::Duration;
use tokio::net::UdpSocket;
use twoping::config::KeyEntry;
use twoping::crypto::{AuthDigest, EncryptMethod, SecurityConfig};
use twoping::engine::{run_engine, EngineConfig, TargetSpec};
use twoping::protocol::{opcodes, Packet, MAGIC_NUMBER};

#[test]
fn test_plaintext_roundtrip_and_v1_opcodes() {
    let sec = SecurityConfig::default();

    let mut pkt = Packet::new();
    pkt.reply_requested = true;
    pkt.in_reply_to = Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    pkt.courtesy_expires = vec![[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]];
    pkt.ping_time_us = Some(14_250);
    pkt.host_latency_us = Some(320);
    pkt.investigate = vec![[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]];
    pkt.tx_timestamp_ns = Some(1_794_611_520_123_456_789);
    pkt.rx_timestamp_ns = Some(1_794_611_520_128_987_654);
    pkt.min_size = 180;
    pkt.pad_pattern = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let wire = pkt.encode(&sec);
    assert_eq!(wire.len(), 180);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), MAGIC_NUMBER);

    let decoded = Packet::decode(&wire, &sec).expect("Valid plaintext packet should decode");
    assert_eq!(decoded.message_id, pkt.message_id);
    assert!(decoded.reply_requested);
    assert_eq!(decoded.in_reply_to, pkt.in_reply_to);
    assert_eq!(decoded.courtesy_expires, pkt.courtesy_expires);
    assert_eq!(decoded.ping_time_us, Some(14_250));
    assert_eq!(decoded.host_latency_us, Some(320));
    assert_eq!(decoded.investigate, pkt.investigate);
    assert_eq!(decoded.tx_timestamp_ns, Some(1_794_611_520_123_456_789));
    assert_eq!(decoded.rx_timestamp_ns, Some(1_794_611_520_128_987_654));
}

#[test]
fn test_checksum_tampering_rejected() {
    let sec = SecurityConfig::default();
    let pkt = Packet::new();
    let mut wire = pkt.encode(&sec);

    let last_idx = wire.len() - 1;
    wire[last_idx] ^= 0x01;

    let err = Packet::decode(&wire, &sec).unwrap_err();
    assert_eq!(err, "Checksum mismatch");
}

#[test]
fn test_hmac_authentication_digests_and_tamper_rejection() {
    for digest in [
        AuthDigest::HmacMd5,
        AuthDigest::HmacSha256,
        AuthDigest::HmacSha512,
    ] {
        let sender_sec = SecurityConfig::new(
            Some("super-secret-key"),
            digest,
            None,
            EncryptMethod::ChaCha20Poly1305,
        );
        let wrong_sec = SecurityConfig::new(
            Some("wrong-secret-key"),
            digest,
            None,
            EncryptMethod::ChaCha20Poly1305,
        );
        let no_auth_sec = SecurityConfig::default();

        let mut pkt = Packet::new();
        pkt.reply_requested = true;
        pkt.ping_time_us = Some(5_000);

        let wire = pkt.encode(&sender_sec);
        let outer_flags = u16::from_be_bytes([wire[10], wire[11]]);
        assert_ne!(outer_flags & opcodes::HMAC, 0);

        let decoded = Packet::decode(&wire, &sender_sec).expect("Valid HMAC should succeed");
        assert_eq!(decoded.ping_time_us, Some(5_000));

        assert_eq!(
            Packet::decode(&wire, &wrong_sec).unwrap_err(),
            "HMAC authentication failed"
        );
        assert_eq!(
            Packet::decode(&wire, &no_auth_sec).unwrap_err(),
            "Received HMAC packet without --auth key configured"
        );

        let unsigned_wire = pkt.encode(&no_auth_sec);
        assert_eq!(
            Packet::decode(&unsigned_wire, &sender_sec).unwrap_err(),
            "Rejected unauthenticated packet (--auth required)"
        );
    }
}

#[test]
fn test_multi_key_rotation_aead_and_hmac() {
    let entries = vec![
        KeyEntry {
            id: "2026-q3".into(),
            auth_secret: Some("old-hmac-secret".into()),
            encrypt_secret: Some("old-chacha-secret".into()),
        },
        KeyEntry {
            id: "2026-q4".into(),
            auth_secret: Some("new-hmac-secret".into()),
            encrypt_secret: Some("new-chacha-secret".into()),
        },
    ];

    // Listener holds both Q3 and Q4 keys, defaulting to Q4
    let listener_sec = SecurityConfig::from_keyring(
        &entries,
        Some("2026-q4"),
        AuthDigest::HmacSha256,
        EncryptMethod::ChaCha20Poly1305,
    )
    .unwrap();

    // Client 1 is still sending packets signed/encrypted with Q3
    let client_q3 = SecurityConfig::from_keyring(
        &entries,
        Some("2026-q3"),
        AuthDigest::HmacSha256,
        EncryptMethod::ChaCha20Poly1305,
    )
    .unwrap();

    let mut pkt = Packet::new();
    pkt.reply_requested = true;
    pkt.tx_timestamp_ns = Some(999_888_777);

    let wire = pkt.encode(&client_q3);
    let outer_flags = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(
        outer_flags,
        opcodes::HMAC | opcodes::KEY_ID | opcodes::ENCRYPTED
    );

    // Listener decodes Q3 packet seamlessly and identifies the key ID
    let decoded = Packet::decode(&wire, &listener_sec)
        .expect("Listener should accept retired Q3 key during rotation");
    assert_eq!(decoded.key_id.as_deref(), Some("2026-q3"));
    assert_eq!(decoded.tx_timestamp_ns, Some(999_888_777));

    // A listener that only has Q4 rejects the Q3 packet
    let q4_only_listener = SecurityConfig::from_keyring(
        &entries[1..],
        Some("2026-q4"),
        AuthDigest::HmacSha256,
        EncryptMethod::ChaCha20Poly1305,
    )
    .unwrap();

    assert_eq!(
        Packet::decode(&wire, &q4_only_listener).unwrap_err(),
        "HMAC authentication failed"
    );
}

#[test]
fn test_chacha20_poly1305_aead_and_header_binding() {
    let sec = SecurityConfig::new(
        None,
        AuthDigest::HmacSha256,
        Some("aead-passphrase"),
        EncryptMethod::ChaCha20Poly1305,
    );
    let wrong_sec = SecurityConfig::new(
        None,
        AuthDigest::HmacSha256,
        Some("wrong-aead-passphrase"),
        EncryptMethod::ChaCha20Poly1305,
    );

    let mut pkt = Packet::new();
    pkt.reply_requested = true;
    pkt.in_reply_to = Some([0x42; 6]);
    pkt.host_latency_us = Some(750);

    let wire = pkt.encode(&sec);

    let outer_flags = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(outer_flags, opcodes::ENCRYPTED);

    let decoded = Packet::decode(&wire, &sec).expect("AEAD packet should decode");
    assert!(decoded.reply_requested);
    assert_eq!(decoded.in_reply_to, Some([0x42; 6]));
    assert_eq!(decoded.host_latency_us, Some(750));

    assert_eq!(
        Packet::decode(&wire, &wrong_sec).unwrap_err(),
        "ChaCha20-Poly1305 AEAD authentication or decryption failed"
    );

    // Tamper with the unencrypted message_id in the outer header (AAD binding check)
    let mut tampered = wire.clone();
    tampered[4] ^= 0xFF;
    tampered[2] = 0;
    tampered[3] = 0;
    let csum = recompute_ones_complement(&tampered);
    tampered[2..4].copy_from_slice(&csum.to_be_bytes());

    assert_eq!(
        Packet::decode(&tampered, &sec).unwrap_err(),
        "ChaCha20-Poly1305 AEAD authentication or decryption failed"
    );
}

#[tokio::test]
async fn test_multi_target_aead_3way_loopback() {
    let listener1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();

    let listener2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let sec = SecurityConfig::new(
        None,
        AuthDigest::HmacSha512,
        Some("multi-target-chacha-key"),
        EncryptMethod::ChaCha20Poly1305,
    );

    let sec1 = sec.clone();
    let h1 = tokio::spawn(async move {
        let cfg = EngineConfig {
            listen_mode: true,
            targets: vec![],
            interval: Duration::from_secs(1),
            count: None,
            min_packet_size: 128,
            pad_pattern: vec![],
            quiet: true,
            verbose: false,
            three_way: true,
            json_output: false,
            mtu_discover: false,
            tui_mode: false,
            adaptive: false,
            metrics_port: None,
            security: sec1,
        };
        let _ = run_engine(listener1, cfg).await;
    });

    let sec2 = sec.clone();
    let h2 = tokio::spawn(async move {
        let cfg = EngineConfig {
            listen_mode: true,
            targets: vec![],
            interval: Duration::from_secs(1),
            count: None,
            min_packet_size: 128,
            pad_pattern: vec![],
            quiet: true,
            verbose: false,
            three_way: true,
            json_output: false,
            mtu_discover: false,
            tui_mode: false,
            adaptive: false,
            metrics_port: None,
            security: sec2,
        };
        let _ = run_engine(listener2, cfg).await;
    });

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_cfg = EngineConfig {
        listen_mode: false,
        targets: vec![
            TargetSpec {
                name: "node-alpha".into(),
                addr: addr1,
            },
            TargetSpec {
                name: "node-beta".into(),
                addr: addr2,
            },
        ],
        interval: Duration::from_millis(50),
        count: Some(3),
        min_packet_size: 128,
        pad_pattern: vec![0xAA],
        quiet: true,
        verbose: false,
        three_way: true,
        json_output: false,
        mtu_discover: false,
        tui_mode: false,
        adaptive: false,
        metrics_port: None,
        security: sec,
    };

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        run_engine(client_socket, client_cfg),
    )
    .await
    .expect("Multi-target client should complete within 3 seconds");

    assert!(result.is_ok());
    h1.abort();
    h2.abort();
}

fn recompute_ones_complement(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
}
if let Some(&rem) = chunks.remainder().first() {
sum += (rem as u32) << 8;
}
while (sum >> 16) != 0 {
sum = (sum & 0xFFFF) + (sum >> 16);
}
let res = !(sum as u16);
if res == 0 {
0xFFFF
} else {
res
}
}