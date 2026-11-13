#![no_main]

use libfuzzer_sys::fuzz_target;
use twoping::config::{AppConfigFile, KeyringFile};
use twoping::crypto::{AuthDigest, EncryptMethod, SecurityConfig};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // 1. Fuzz AppConfigFile TOML deserialization + SecurityConfig derivation
    if let Ok(app_cfg) = toml::from_str::<AppConfigFile>(text) {
        if !app_cfg.keys.is_empty() {
            let _ = SecurityConfig::from_keyring(
                &app_cfg.keys,
                app_cfg.active_key_id.as_deref(),
                AuthDigest::HmacSha256,
                EncryptMethod::ChaCha20Poly1305,
            );
            let _ = SecurityConfig::from_keyring(
                &app_cfg.keys,
                app_cfg.active_key_id.as_deref(),
                AuthDigest::HmacSha512,
                EncryptMethod::Aes256Cbc,
            );
        }
    }

    // 2. Fuzz standalone KeyringFile TOML deserialization + SecurityConfig derivation
    if let Ok(kr_cfg) = toml::from_str::<KeyringFile>(text) {
        if !kr_cfg.keys.is_empty() {
            let _ = SecurityConfig::from_keyring(
                &kr_cfg.keys,
                kr_cfg.active_key_id.as_deref(),
                AuthDigest::HmacMd5,
                EncryptMethod::ChaCha20Poly1305,
            );
        }
    }
});
