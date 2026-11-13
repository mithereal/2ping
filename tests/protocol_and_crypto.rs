use std::time::Duration;
use tokio::net::UdpSocket;
use twoping::crypto::{AuthDigest, SecurityConfig};
use twoping::engine::{run_engine, EngineConfig};
use twoping::protocol::{opcodes, Packet, MAGIC_NUMBER};

#[test]
fn test_plaintext_roundtrip_and_opcodes() {
    let sec = SecurityConfig::default();

    let mut pkt = Packet::new();
    pkt.reply_requested = true;
    pkt.in_reply_to = Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    pkt.courtesy_expires = vec![[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]];
    pkt.ping_time_us = Some(14_250);
    pkt.host_latency_us = Some(320);
    pkt.investigate = vec![[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]];
    pkt.min_size = 160;
    pkt.pad_pattern = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let wire = pkt.encode(&sec);
    assert_eq!(wire.len(), 160);
    assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), MAGIC_NUMBER);

    let decoded = Packet::decode(&wire, &sec).expect("Valid plaintext packet should decode");
    assert_eq!(decoded.message_id, pkt.message_id);
    assert!(decoded.reply_requested);
    assert_eq!(decoded.in_reply_to, pkt.in_reply_to);
    assert_eq!(decoded.courtesy_expires, pkt.courtesy_expires);
    assert_eq!(decoded.ping_time_us, Some(14_250));
    assert_eq!(decoded.host_latency_us, Some(320));
    assert_eq!(decoded.investigate, pkt.investigate);
}

#[test]
fn test_checksum_tampering_rejected() {
    let sec = SecurityConfig::default();
    let pkt = Packet::new();
    let mut wire = pkt.encode(&sec);

    // Flip a bit in the padding area
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
        let sender_sec = SecurityConfig::new(Some("super-secret-key"), digest, None);
        let wrong_sec = SecurityConfig::new(Some("wrong-secret-key"), digest, None);
        let no_auth_sec = SecurityConfig::default();

        let mut pkt = Packet::new();
        pkt.reply_requested = true;
        pkt.ping_time_us = Some(5_000);

        let wire = pkt.encode(&sender_sec);

        // Verify HMAC flag is set on the wire
        let outer_flags = u16::from_be_bytes([wire[10], wire[11]]);
        assert_ne!(outer_flags & opcodes::HMAC, 0);

        // 1. Valid key succeeds
        let decoded = Packet::decode(&wire, &sender_sec).expect("Valid HMAC should succeed");
        assert_eq!(decoded.ping_time_us, Some(5_000));

        // 2. Wrong key fails
        assert_eq!(
            Packet::decode(&wire, &wrong_sec).unwrap_err(),
            "HMAC authentication failed"
        );

        // 3. Unauthenticated peer rejects signed packet
        assert_eq!(
            Packet::decode(&wire, &no_auth_sec).unwrap_err(),
            "Received HMAC packet without --auth key configured"
        );

        // 4. Signed peer rejects unsigned packet
        let unsigned_wire = pkt.encode(&no_auth_sec);
        assert_eq!(
            Packet::decode(&unsigned_wire, &sender_sec).unwrap_err(),
            "Rejected unauthenticated packet (--auth required)"
        );
    }
}

#[test]
fn test_aes256_cbc_encryption_and_encrypt_then_mac() {
    let sec = SecurityConfig::new(
        Some("hmac-passphrase"),
        AuthDigest::HmacSha256,
        Some("aes-encryption-passphrase"),
    );
    let wrong_enc_sec = SecurityConfig::new(
        Some("hmac-passphrase"),
        AuthDigest::HmacSha256,
        Some("bad-encryption-passphrase"),
    );

    let mut pkt = Packet::new();
    pkt.reply_requested = true;
    pkt.in_reply_to = Some([0x99; 6]);
    pkt.ping_time_us = Some(88_888);

    let wire = pkt.encode(&sec);

    // Outer flags should ONLY have HMAC and ENCRYPTED set (inner flags are hidden)
    let outer_flags = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(outer_flags, opcodes::HMAC | opcodes::ENCRYPTED);

    // Round-trip decode with matching keys
    let decoded = Packet::decode(&wire, &sec).expect("Authenticated + encrypted packet decodes");
    assert!(decoded.reply_requested);
    assert_eq!(decoded.in_reply_to, Some([0x99; 6]));
    assert_eq!(decoded.ping_time_us, Some(88_888));

    // Wrong encryption key fails decryption
    assert_eq!(
        Packet::decode(&wire, &wrong_enc_sec).unwrap_err(),
        "AES-256-CBC decryption or PKCS7 padding failed"
    );

    // Tampering with ciphertext is caught by HMAC BEFORE decryption is attempted
    let mut tampered_wire = wire.clone();
    tampered_wire[65] ^= 0xFF;
    // Recompute valid outer checksum to ensure HMAC catches it rather than checksum
    tampered_wire[2] = 0;
    tampered_wire[3] = 0;
    let csum = recompute_ones_complement(&tampered_wire);
    tampered_wire[2..4].copy_from_slice(&csum.to_be_bytes());

    assert_eq!(
        Packet::decode(&tampered_wire, &sec).unwrap_err(),
        "HMAC authentication failed"
    );
}

#[tokio::test]
async fn test_end_to_end_encrypted_3way_loopback() {
    let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener_socket.local_addr().unwrap();

    let listener_sec = SecurityConfig::new(
        Some("loopback-auth"),
        AuthDigest::HmacSha512,
        Some("loopback-enc"),
    );
    let client_sec = listener_sec.clone();

    // Spawn background listener
    let listener_handle = tokio::spawn(async move {
        let cfg = EngineConfig {
            listen_mode: true,
            target_addr: None,
            target_name: "listener".into(),
            interval: Duration::from_secs(1),
            count: None,
            min_packet_size: 128,
            pad_pattern: vec![],
            quiet: true,
            verbose: false,
            three_way: true,
            security: listener_sec,
        };
        let _ = run_engine(listener_socket, cfg).await;
    });

    // Run client sending 3 pings at 50ms intervals
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_cfg = EngineConfig {
        listen_mode: false,
        target_addr: Some(listener_addr),
        target_name: "127.0.0.1".into(),
        interval: Duration::from_millis(50),
        count: Some(3),
        min_packet_size: 128,
        pad_pattern: vec![0xAA],
        quiet: true,
        verbose: false,
        three_way: true,
        security: client_sec,
    };

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        run_engine(client_socket, client_cfg),
    )
    .await
    .expect("Client should finish within 3 seconds");

    assert!(result.is_ok());
    listener_handle.abort();
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
