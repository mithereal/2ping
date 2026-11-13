use crate::config::KeyEntry;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const PBKDF2_ITERATIONS: u32 = 10_000;
const AUTH_SALT: &[u8] = b"2ping-hmac-auth-salt-v1";
const ENC_SALT: &[u8] = b"2ping-aes256-cbc-salt-v1";
const AEAD_SALT: &[u8] = b"2ping-chacha20poly1305-salt-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDigest {
    HmacMd5,
    HmacSha256,
    HmacSha512,
}

impl AuthDigest {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "hmac-md5" | "md5" => Ok(Self::HmacMd5),
            "hmac-sha256" | "sha256" => Ok(Self::HmacSha256),
            "hmac-sha512" | "sha512" => Ok(Self::HmacSha512),
            _ => Err(format!(
                "Unsupported auth digest '{}'. Expected hmac-md5, hmac-sha256, or hmac-sha512",
                s
            )),
        }
    }

    pub fn digest_id(&self) -> u8 {
        match self {
            Self::HmacMd5 => 1,
            Self::HmacSha256 => 2,
            Self::HmacSha512 => 3,
        }
    }

    pub fn tag_len(&self) -> usize {
        match self {
            Self::HmacMd5 => 16,
            Self::HmacSha256 => 32,
            Self::HmacSha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptMethod {
    #[default]
    ChaCha20Poly1305,
    Aes256Cbc,
}

impl EncryptMethod {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "chacha20-poly1305" | "chacha20" => Ok(Self::ChaCha20Poly1305),
            "aes256-cbc" | "aes-256-cbc" => Ok(Self::Aes256Cbc),
            _ => Err(format!(
                "Unsupported encrypt method '{}'. Expected chacha20-poly1305 or aes256-cbc",
                s
            )),
        }
    }
}

#[derive(Clone)]
pub struct DerivedKeyMaterial {
    pub id: String,
    pub auth_key: Option<[u8; 32]>,
    pub encrypt_key: Option<[u8; 32]>,
}

impl DerivedKeyMaterial {
    pub fn from_secrets(
        id: impl Into<String>,
        auth_secret: Option<&str>,
        encrypt_secret: Option<&str>,
        encrypt_method: EncryptMethod,
    ) -> Self {
        let auth_key = auth_secret.map(|secret| {
            let mut key = [0u8; 32];
            pbkdf2_hmac::<Sha256>(secret.as_bytes(), AUTH_SALT, PBKDF2_ITERATIONS, &mut key);
            key
        });

        let salt = match encrypt_method {
            EncryptMethod::ChaCha20Poly1305 => AEAD_SALT,
            EncryptMethod::Aes256Cbc => ENC_SALT,
        };

        let encrypt_key = encrypt_secret.map(|secret| {
            let mut key = [0u8; 32];
            pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
            key
        });

        Self {
            id: id.into(),
            auth_key,
            encrypt_key,
        }
    }
}

#[derive(Clone, Default)]
pub struct SecurityConfig {
    pub active_key_id: String,
    pub keyring: HashMap<String, DerivedKeyMaterial>,
    pub auth_digest: Option<AuthDigest>,
    pub encrypt_method: EncryptMethod,
}

impl SecurityConfig {
    pub fn new(
        auth_secret: Option<&str>,
        digest: AuthDigest,
        encrypt_secret: Option<&str>,
        encrypt_method: EncryptMethod,
    ) -> Self {
        let mut keyring = HashMap::new();
        let active_id = "default".to_string();

        if auth_secret.is_some() || encrypt_secret.is_some() {
            keyring.insert(
                active_id.clone(),
                DerivedKeyMaterial::from_secrets(
                    active_id.clone(),
                    auth_secret,
                    encrypt_secret,
                    encrypt_method,
                ),
            );
        }

        Self {
            active_key_id: active_id,
            keyring,
            auth_digest: if auth_secret.is_some() {
                Some(digest)
            } else {
                None
            },
            encrypt_method,
        }
    }

    pub fn from_keyring(
        entries: &[KeyEntry],
        active_id: Option<&str>,
        digest: AuthDigest,
        encrypt_method: EncryptMethod,
    ) -> Result<Self, String> {
        if entries.is_empty() {
            return Err("Keyring contains no key entries".into());
        }
        let mut keyring = HashMap::new();
        let mut has_auth = false;

        for entry in entries {
            if entry.auth_secret.is_some() {
                has_auth = true;
            }
            keyring.insert(
                entry.id.clone(),
                DerivedKeyMaterial::from_secrets(
                    entry.id.clone(),
                    entry.auth_secret.as_deref(),
                    entry.encrypt_secret.as_deref(),
                    encrypt_method,
                ),
            );
        }

        let chosen_active = match active_id {
            Some(id) => {
                if !keyring.contains_key(id) {
                    return Err(format!("Active key id '{}' not found in keyring", id));
                }
                id.to_string()
            }
            None => entries.id.clone(),
        };

        Ok(Self {
            active_key_id: chosen_active,
            keyring,
            auth_digest: if has_auth { Some(digest) } else { None },
            encrypt_method,
        })
    }

    pub fn active_material(&self) -> Option<&DerivedKeyMaterial> {
        self.keyring.get(&self.active_key_id)
    }

    pub fn requires_auth(&self) -> bool {
        self.keyring.values().any(|k| k.auth_key.is_some())
    }

    pub fn requires_encryption(&self) -> bool {
        self.keyring.values().any(|k| k.encrypt_key.is_some())
    }

    pub fn resolve_key(&self, key_id: Option<&str>) -> Option<&DerivedKeyMaterial> {
        match key_id {
            Some(id) => self.keyring.get(id),
            None => self.active_material(),
        }
    }

    pub fn compute_hmac(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mat = self.active_material()?;
        let key = mat.auth_key.as_ref()?;
        let digest = self.auth_digest?;
        let mut out = vec![digest.digest_id()];

        match digest {
            AuthDigest::HmacMd5 => {
                let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC key init");
                mac.update(data);
                out.extend_from_slice(&mac.finalize().into_bytes());
            }
            AuthDigest::HmacSha256 => {
                let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC key init");
                mac.update(data);
                out.extend_from_slice(&mac.finalize().into_bytes());
            }
            AuthDigest::HmacSha512 => {
                let mut mac = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC key init");
                mac.update(data);
                out.extend_from_slice(&mac.finalize().into_bytes());
            }
        }
        Some(out)
    }

    pub fn verify_hmac(&self, data: &[u8], field_payload: &[u8], key_id: Option<&str>) -> bool {
        let Some(digest) = self.auth_digest else {
            return false;
        };
        if field_payload.len() != 1 + digest.tag_len() || field_payload != digest.digest_id() {
            return false;
        }
        let Some(mat) = self.resolve_key(key_id) else {
            return false;
        };
        let Some(key) = mat.auth_key.as_ref() else {
            return false;
        };

        let mut expected = vec![digest.digest_id()];
        match digest {
            AuthDigest::HmacMd5 => {
                let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC key init");
                mac.update(data);
                expected.extend_from_slice(&mac.finalize().into_bytes());
            }
            AuthDigest::HmacSha256 => {
                let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC key init");
                mac.update(data);
                expected.extend_from_slice(&mac.finalize().into_bytes());
            }
            AuthDigest::HmacSha512 => {
                let mut mac = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC key init");
                mac.update(data);
                expected.extend_from_slice(&mac.finalize().into_bytes());
            }
        }

        expected.ct_eq(field_payload).into()
    }

    pub fn encrypt_chacha20_poly1305(&self, plaintext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let mat = self.active_material()?;
        let key = mat.encrypt_key.as_ref()?;
        let cipher = ChaCha20Poly1305::new(key.into());

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .ok()?;

        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Some(out)
    }

    pub fn decrypt_chacha20_poly1305(
        &self,
        nonce_and_ct: &[u8],
        aad: &[u8],
        key_id: Option<&str>,
    ) -> Result<Vec<u8>, &'static str> {
        let mat = self
            .resolve_key(key_id)
            .ok_or("Unknown or unconfigured encryption key ID")?;
        let key = mat
            .encrypt_key
            .as_ref()
.ok_or("Selected key entry has no encryption secret")?;
if nonce_and_ct.len() < 12 + 16 {
return Err("Invalid ChaCha20-Poly1305 ciphertext length");
}
let (nonce_bytes, ct) = nonce_and_ct.split_at(12);
let cipher = ChaCha20Poly1305::new(key.into());
let nonce = Nonce::from_slice(nonce_bytes);
cipher
.decrypt(nonce, Payload { msg: ct, aad })
.map_err(|_| "ChaCha20-Poly1305 AEAD authentication or decryption failed")
}
pub fn encrypt_aes256_cbc(&self, plaintext: &[u8]) -> Option<Vec> {
let mat = self.active_material()?;
let key = mat.encrypt_key.as_ref()?;
let mut iv = [0u8; 16];
rand::thread_rng().fill_bytes(&mut iv);
let ct = Aes256CbcEnc::new(key.into(), &iv.into())
.encrypt_padded_vec_mut::(plaintext);
let mut out = Vec::with_capacity(16 + ct.len());
out.extend_from_slice(&iv);
out.extend_from_slice(&ct);
Some(out)
}
pub fn decrypt_aes256_cbc(
&self,
iv_and_ct: &[u8],
key_id: Option<&str>,
) -> Result<Vec, &'static str> {
let mat = self
.resolve_key(key_id)
.ok_or("Unknown or unconfigured encryption key ID")?;
let key = mat
.encrypt_key
.as_ref()
.ok_or("Selected key entry has no encryption secret")?;
if iv_and_ct.len() < 32 || (iv_and_ct.len() - 16) % 16 != 0 {
return Err("Invalid AES-256-CBC ciphertext length");
}
let (iv, ct) = iv_and_ct.split_at(16);
Aes256CbcDec::new(key.into(), iv.into())
.decrypt_padded_vec_mut::(ct)
.map_err(|_| "AES-256-CBC decryption or PKCS7 padding failed")
}
}