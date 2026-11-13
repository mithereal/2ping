use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const PBKDF2_ITERATIONS: u32 = 10_000;
const AUTH_SALT: &[u8] = b"2ping-hmac-auth-salt-v1";
const ENC_SALT: &[u8] = b"2ping-aes256-cbc-salt-v1";

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

#[derive(Clone, Default)]
pub struct SecurityConfig {
    pub auth_key: Option<[u8; 32]>,
    pub auth_digest: Option<AuthDigest>,
    pub encrypt_key: Option<[u8; 32]>,
}

impl SecurityConfig {
    pub fn new(
        auth_secret: Option<&str>,
        digest: AuthDigest,
        encrypt_secret: Option<&str>,
    ) -> Self {
        let auth_key = auth_secret.map(|secret| {
            let mut key = [0u8; 32];
            pbkdf2_hmac::<Sha256>(secret.as_bytes(), AUTH_SALT, PBKDF2_ITERATIONS, &mut key);
            key
        });

        let encrypt_key = encrypt_secret.map(|secret| {
            let mut key = [0u8; 32];
            pbkdf2_hmac::<Sha256>(secret.as_bytes(), ENC_SALT, PBKDF2_ITERATIONS, &mut key);
            key
        });

        Self {
            auth_key,
            auth_digest: if auth_secret.is_some() {
                Some(digest)
            } else {
                None
            },
            encrypt_key,
        }
    }

    /// Computes `[digest_id (1B) | mac_tag]` over the provided message slice.
    pub fn compute_hmac(&self, data: &[u8]) -> Option<Vec<u8>> {
        let key = self.auth_key.as_ref()?;
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

    /// Constant-time HMAC verification against `field_payload` (`[digest_id | tag]`).
    pub fn verify_hmac(&self, data: &[u8], field_payload: &[u8]) -> bool {
        let Some(digest) = self.auth_digest else {
            return false;
        };
        if field_payload.len() != 1 + digest.tag_len() {
            return false;
        }
        if field_payload[0] != digest.digest_id() {
            return false;
        }
        let Some(expected) = self.compute_hmac(data) else {
            return false;
        };
        expected.ct_eq(field_payload).into()
    }

    /// Encrypts plaintext using AES-256-CBC with a random 16-byte IV.
    /// Returns `[16-byte IV || ciphertext]`.
    pub fn encrypt_aes256_cbc(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let key = self.encrypt_key.as_ref()?;
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let ct = Aes256CbcEnc::new(key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut out = Vec::with_capacity(16 + ct.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        Some(out)
    }

    /// Decrypts `[16-byte IV || ciphertext]` using AES-256-CBC.
    pub fn decrypt_aes256_cbc(&self, iv_and_ct: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key = self
            .encrypt_key
            .as_ref()
            .ok_or("Received encrypted packet without --encrypt key configured")?;

        if iv_and_ct.len() < 32 || (iv_and_ct.len() - 16) % 16 != 0 {
            return Err("Invalid AES-256-CBC ciphertext length");
        }

        let (iv, ct) = iv_and_ct.split_at(16);
        Aes256CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|_| "AES-256-CBC decryption or PKCS7 padding failed")
    }
}
