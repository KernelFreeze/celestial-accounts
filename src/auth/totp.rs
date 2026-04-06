use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, TOTP};

use crate::auth::verifier::{CredentialVerifier, VerificationError};
use crate::database::models::Credential;

const NONCE_LEN: usize = 12;

/// Encrypts and decrypts TOTP secrets using AES-256-GCM.
///
/// Storage format in `credential_data`: `nonce (12 bytes) || ciphertext+tag`.
pub struct TotpEncryptor {
    cipher: Aes256Gcm,
}

impl TotpEncryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("key is 32 bytes"),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .expect("encryption must not fail");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, VerificationError> {
        if data.len() < NONCE_LEN {
            return Err(VerificationError::Internal("credential data too short".into()));
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| VerificationError::Internal(e.to_string().into()))
    }
}

/// Verifies TOTP codes against encrypted secrets stored in the credentials
/// table. Codes are SHA-256 hashed before constant-time comparison.
pub struct TotpVerifier {
    encryptor: TotpEncryptor,
    dummy_secret: Vec<u8>,
}

impl TotpVerifier {
    pub fn new(encryption_key: [u8; 32]) -> Self {
        let encryptor = TotpEncryptor::new(&encryption_key);
        // Pre-encrypt a dummy secret so dummy_verify does equivalent work.
        let dummy_secret = encryptor.encrypt(b"dummy_totp_secret_padding_bytes!");
        Self {
            encryptor,
            dummy_secret,
        }
    }

    fn verify_code(secret: &[u8], code: &str) -> Result<(), VerificationError> {
        let totp = build_totp(secret)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let submitted_hash = Sha256::digest(code.as_bytes());

        // Check current window and ±1 for clock skew tolerance.
        let steps = [now.saturating_sub(30), now, now + 30];
        for step in steps {
            let expected = totp.generate(step);
            let expected_hash = Sha256::digest(expected.as_bytes());
            if submitted_hash.ct_eq(&expected_hash).into() {
                return Ok(());
            }
        }

        Err(VerificationError::InvalidCredentials)
    }
}

fn build_totp(secret: &[u8]) -> Result<TOTP, VerificationError> {
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.to_vec()).map_err(|e| VerificationError::Internal(Box::new(e)))
}

impl CredentialVerifier for TotpVerifier {
    type Payload = str;

    async fn verify(&self, credential: &Credential, code: &Self::Payload) -> Result<(), VerificationError> {
        let secret = self.encryptor.decrypt(&credential.credential_data)?;
        Self::verify_code(&secret, code)
    }

    async fn dummy_verify(&self) {
        // Perform equivalent decrypt + code generation + comparison work.
        let secret = self.encryptor.decrypt(&self.dummy_secret).unwrap_or_default();
        let _ = Self::verify_code(&secret, "000000");
    }
}
