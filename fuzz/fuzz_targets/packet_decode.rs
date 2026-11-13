#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use twoping::crypto::{AuthDigest, EncryptMethod, SecurityConfig};
use twoping::protocol::Packet;

struct SecurityConfigs {
    plaintext: SecurityConfig,
    hmac_sha256: SecurityConfig,
    chacha_aead: SecurityConfig,
    aes_cbc_hmac: SecurityConfig,
}

fn configs() -> &'static SecurityConfigs {
    static CONFIGS: OnceLock<SecurityConfigs> = OnceLock::new();
    CONFIGS.get_or_init(|| SecurityConfigs {
        plaintext: SecurityConfig::default(),
        hmac_sha256: SecurityConfig::new(
            Some("fuzz-hmac-secret"),
            AuthDigest::HmacSha256,
            None,
            EncryptMethod::ChaCha20Poly1305,
        ),
        chacha_aead: SecurityConfig::new(
            None,
            AuthDigest::HmacSha256,
            Some("fuzz-aead-secret"),
            EncryptMethod::ChaCha20Poly1305,
        ),
        aes_cbc_hmac: SecurityConfig::new(
            Some("fuzz-hmac-secret"),
            AuthDigest::HmacSha512,
            Some("fuzz-aes-secret"),
            EncryptMethod::Aes256Cbc,
        ),
    })
}

fuzz_target!(|data: &[u8]| {
    let cfgs = configs();

    // 1. Feed raw fuzzer bytes directly into all decoder paths (must never panic)
    let _ = Packet::decode(data, &cfgs.plaintext);
    let _ = Packet::decode(data, &cfgs.hmac_sha256);
    let _ = Packet::decode(data, &cfgs.chacha_aead);
    let _ = Packet::decode(data, &cfgs.aes_cbc_hmac);

    // 2. Prefix fuzzer bytes with valid "2P" magic + valid checksum so the fuzzer
    //    deeply exercises opcode TLV parsing, length bounds, and decryption routines
    if data.len() >= 8 {
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&0x3250u16.to_be_bytes()); // Magic "2P"
        framed.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        framed.extend_from_slice(data);

        let csum = ones_complement_checksum(&framed);
        framed[2..4].copy_from_slice(&csum.to_be_bytes());

        let _ = Packet::decode(&framed, &cfgs.plaintext);
        let _ = Packet::decode(&framed, &cfgs.hmac_sha256);
        let _ = Packet::decode(&framed, &cfgs.chacha_aead);
        let _ = Packet::decode(&framed, &cfgs.aes_cbc_hmac);
    }
});

fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk, chunk]) as u32;
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
