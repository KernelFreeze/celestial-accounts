use argon2::{Argon2, PasswordHasher};
use hmac::{Hmac, Mac};
use phc::{PasswordHash, Salt};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sha2::Sha256;

use crate::auth::verifier::{CredentialVerifier, VerificationError};
use crate::database::models::Credential;

type HmacSha256 = Hmac<Sha256>;

pub struct PasswordVerifier {
    pepper: Vec<u8>,
    dummy_hash: PasswordHash,
}

impl PasswordVerifier {
    pub fn new(pepper: Vec<u8>) -> Self {
        let mut rng = UnwrapErr(SysRng);
        let salt = Salt::from_rng(&mut rng);

        let dummy_hash = Argon2::default()
            .hash_password_with_salt(b"dummy_password_for_timing_equalization", &salt)
            .expect("dummy hash generation must not fail")
            .to_owned();

        Self { pepper, dummy_hash }
    }

    /// Apply HMAC-SHA-256 pre-hash: HMAC(pepper, password) → hex string.
    /// The hex output becomes the input to Argon2id.
    fn peppered(&self, password: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.pepper).expect("HMAC accepts any key length");
        mac.update(password.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

impl CredentialVerifier for PasswordVerifier {
    type Payload = str;

    async fn verify(&self, credential: &Credential, password: &Self::Payload) -> Result<(), VerificationError> {
        let peppered = self.peppered(password);

        let hash_str =
            std::str::from_utf8(&credential.credential_data).map_err(|e| VerificationError::Internal(Box::new(e)))?;

        let parsed_hash = PasswordHash::new(hash_str).map_err(|e| VerificationError::Internal(e.to_string().into()))?;

        argon2::PasswordVerifier::verify_password(&Argon2::default(), peppered.as_bytes(), &parsed_hash)
            .map_err(|_| VerificationError::InvalidCredentials)
    }

    async fn dummy_verify(&self) {
        let _ = argon2::PasswordVerifier::verify_password(
            &Argon2::default(),
            b"wrong_password_on_purpose",
            &self.dummy_hash,
        );
    }
}
