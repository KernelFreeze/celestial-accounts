use rusty_paseto::prelude::*;
use serde::Deserialize;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Holds the cryptographic keys needed for PASETO v4 token operations.
///
/// - `signing_key`: Ed25519 private key bytes (64 bytes) for v4.public access
///   tokens.
/// - `local_key`: 256-bit symmetric key for v4.local partial (MFA) tokens.
/// - `key_id`: Identifier placed in the token footer so verifiers can select
///   the correct public key during key rotation.
pub struct PasetoKeys {
    signing_key: Vec<u8>,
    local_key: Vec<u8>,
    key_id: String,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("failed to build token: {0}")]
    Build(String),

    #[error("invalid token: {0}")]
    Invalid(String),
}

/// Claims extracted from a v4.local partial (MFA) token.
#[derive(Debug)]
pub struct PartialTokenClaims {
    pub account_id: Uuid,
}

#[derive(Deserialize)]
struct PartialPayload {
    sub: String,
    purpose: String,
}

impl PasetoKeys {
    pub fn new(signing_key: Vec<u8>, local_key: Vec<u8>, key_id: String) -> Self {
        Self {
            signing_key,
            local_key,
            key_id,
        }
    }

    fn footer(&self) -> String {
        serde_json::json!({ "kid": self.key_id }).to_string()
    }

    /// Issue a v4.public access token (Ed25519-signed) with a caller-provided
    /// lifetime.
    pub fn issue_access_token(
        &self, account_id: Uuid, session_id: Uuid, lifetime: Duration,
    ) -> Result<String, TokenError> {
        let now = OffsetDateTime::now_utc();
        let exp = now + lifetime;
        let jti = Uuid::now_v7();

        let sub = account_id.to_string();
        let jti_str = jti.to_string();
        let iat = now.format(&Rfc3339).unwrap();
        let exp_str = exp.format(&Rfc3339).unwrap();
        let sid = session_id.to_string();
        let footer = self.footer();

        let key = PasetoAsymmetricPrivateKey::<V4, Public>::from(self.signing_key.as_slice());

        let token = PasetoBuilder::<V4, Public>::default()
            .set_claim(SubjectClaim::from(sub.as_str()))
            .set_claim(TokenIdentifierClaim::from(jti_str.as_str()))
            .set_claim(IssuedAtClaim::try_from(iat.as_str()).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(ExpirationClaim::try_from(exp_str.as_str()).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(CustomClaim::try_from(("sid", sid.as_str())).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_footer(Footer::from(footer.as_str()))
            .build(&key)
            .map_err(|e| TokenError::Build(e.to_string()))?;

        Ok(token)
    }

    /// Issue a v4.local partial token (encrypted) for MFA challenges with a
    /// caller-provided lifetime. Only grants access to the MFA verification
    /// endpoint.
    pub fn issue_partial_token(&self, account_id: Uuid, lifetime: Duration) -> Result<String, TokenError> {
        let now = OffsetDateTime::now_utc();
        let exp = now + lifetime;

        let sub = account_id.to_string();
        let iat = now.format(&Rfc3339).unwrap();
        let exp_str = exp.format(&Rfc3339).unwrap();

        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
            <&[u8; 32]>::try_from(self.local_key.as_slice()).expect("local key must be 32 bytes"),
        ));

        let token = PasetoBuilder::<V4, Local>::default()
            .set_claim(SubjectClaim::from(sub.as_str()))
            .set_claim(IssuedAtClaim::try_from(iat.as_str()).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(ExpirationClaim::try_from(exp_str.as_str()).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(CustomClaim::try_from(("purpose", "mfa")).map_err(|e| TokenError::Build(e.to_string()))?)
            .build(&key)
            .map_err(|e| TokenError::Build(e.to_string()))?;

        Ok(token)
    }

    /// Decrypt and validate a v4.local partial token, returning the embedded
    /// account ID. Rejects tokens whose `purpose` is not `"mfa"`.
    pub fn verify_partial_token(&self, token: &str) -> Result<PartialTokenClaims, TokenError> {
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(
            <&[u8; 32]>::try_from(self.local_key.as_slice()).expect("local key must be 32 bytes"),
        ));

        let value = PasetoParser::<V4, Local>::default()
            .parse(token, &key)
            .map_err(|e| TokenError::Invalid(e.to_string()))?;

        let payload: PartialPayload = serde_json::from_value(value).map_err(|e| TokenError::Invalid(e.to_string()))?;

        if payload.purpose != "mfa" {
            return Err(TokenError::Invalid("token purpose is not mfa".into()));
        }

        let account_id = Uuid::parse_str(&payload.sub).map_err(|e| TokenError::Invalid(e.to_string()))?;

        Ok(PartialTokenClaims { account_id })
    }
}
