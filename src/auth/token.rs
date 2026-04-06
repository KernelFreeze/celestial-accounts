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

/// Optional/customizable values for access token issuance.
///
/// Defaults are intentionally permissive for first-party session tokens:
/// - `audience`: `"first_party"`
/// - `scope`: `"*"`
/// - `organization_id`: `None`
/// - `issuer`: `"celestial-accounts"`
#[derive(Debug, Clone)]
pub struct AccessTokenOptions {
    pub audience: String,
    pub scope: String,
    pub organization_id: Option<Uuid>,
    pub issuer: String,
}

impl Default for AccessTokenOptions {
    fn default() -> Self {
        Self {
            audience: "first_party".to_owned(),
            scope: "*".to_owned(),
            organization_id: None,
            issuer: "celestial-accounts".to_owned(),
        }
    }
}

/// Claims extracted from a verified v4.public access token.
///
/// Includes identity/session claims and authorization context claims.
#[derive(Debug)]
pub struct AccessTokenClaims {
    pub account_id: Uuid,
    pub session_id: Uuid,
    pub token_id: Uuid,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,

    pub audience: String,
    pub scope: String,
    pub organization_id: Option<Uuid>,
    pub issuer: String,
}

impl AccessTokenClaims {
    /// Return all scopes as a vector split by ASCII whitespace.
    pub fn scopes(&self) -> Vec<&str> {
        self.scope.split_ascii_whitespace().filter(|s| !s.is_empty()).collect()
    }

    /// Check whether this token contains `required_scope`.
    ///
    /// The wildcard scope `"*"` grants access to any required scope.
    pub fn has_scope(&self, required_scope: &str) -> bool {
        let required = required_scope.trim();
        if required.is_empty() {
            return false;
        }

        self.scope
            .split_ascii_whitespace()
            .any(|s| s == "*" || s.eq_ignore_ascii_case(required))
    }

    /// Check whether this token has at least one required scope.
    pub fn has_any_scope<'a, I>(&self, required_scopes: I) -> bool
    where
        I: IntoIterator<Item = &'a str>, {
        required_scopes.into_iter().any(|scope| self.has_scope(scope))
    }

    /// Check whether this token has all required scopes.
    pub fn has_all_scopes<'a, I>(&self, required_scopes: I) -> bool
    where
        I: IntoIterator<Item = &'a str>, {
        required_scopes.into_iter().all(|scope| self.has_scope(scope))
    }

    /// Audience match helper.
    pub fn is_for_audience(&self, audience: &str) -> bool {
        self.audience.eq_ignore_ascii_case(audience.trim())
    }
}

#[derive(Deserialize)]
struct PartialPayload {
    sub: String,
    purpose: String,
}

#[derive(Deserialize)]
struct AccessPayload {
    sub: String,
    sid: String,
    jti: String,
    iat: String,
    exp: String,

    aud: Option<String>,
    scope: Option<String>,
    org_id: Option<String>,
    iss: Option<String>,
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
    /// lifetime and default authorization options.
    pub fn issue_access_token(
        &self, account_id: Uuid, session_id: Uuid, lifetime: Duration,
    ) -> Result<String, TokenError> {
        self.issue_access_token_with_options(account_id, session_id, lifetime, &AccessTokenOptions::default())
    }

    /// Issue a v4.public access token with explicit audience/scope/issuer data.
    pub fn issue_access_token_with_options(
        &self, account_id: Uuid, session_id: Uuid, lifetime: Duration, options: &AccessTokenOptions,
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
        let org_id = options.organization_id.map(|id| id.to_string());

        let mut builder = PasetoBuilder::<V4, Public>::default();
        builder
            .set_claim(SubjectClaim::from(sub.as_str()))
            .set_claim(TokenIdentifierClaim::from(jti_str.as_str()))
            .set_claim(IssuedAtClaim::try_from(iat.as_str()).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(ExpirationClaim::try_from(exp_str.as_str()).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(CustomClaim::try_from(("sid", sid.as_str())).map_err(|e| TokenError::Build(e.to_string()))?)
            .set_claim(
                CustomClaim::try_from(("aud", options.audience.as_str()))
                    .map_err(|e| TokenError::Build(e.to_string()))?,
            )
            .set_claim(
                CustomClaim::try_from(("scope", options.scope.as_str()))
                    .map_err(|e| TokenError::Build(e.to_string()))?,
            )
            .set_claim(
                CustomClaim::try_from(("iss", options.issuer.as_str()))
                    .map_err(|e| TokenError::Build(e.to_string()))?,
            );

        if let Some(org_id) = org_id.as_deref() {
            builder.set_claim(CustomClaim::try_from(("org_id", org_id)).map_err(|e| TokenError::Build(e.to_string()))?);
        }

        builder.set_footer(Footer::from(footer.as_str()));

        let token = builder.build(&key).map_err(|e| TokenError::Build(e.to_string()))?;

        Ok(token)
    }

    /// Verify a v4.public access token and extract claims used by revocation
    /// and session-management workflows.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, TokenError> {
        let public_key_bytes: [u8; 32] = self
            .signing_key
            .get(32..64)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| TokenError::Invalid("signing key is not a 64-byte Ed25519 private key".into()))?;
        let public_key = Key::<32>::from(&public_key_bytes);
        let key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

        let value = PasetoParser::<V4, Public>::default()
            .parse(token, &key)
            .map_err(|e| TokenError::Invalid(e.to_string()))?;

        let payload: AccessPayload = serde_json::from_value(value).map_err(|e| TokenError::Invalid(e.to_string()))?;

        let account_id = Uuid::parse_str(&payload.sub).map_err(|e| TokenError::Invalid(e.to_string()))?;
        let session_id = Uuid::parse_str(&payload.sid).map_err(|e| TokenError::Invalid(e.to_string()))?;
        let token_id = Uuid::parse_str(&payload.jti).map_err(|e| TokenError::Invalid(e.to_string()))?;
        let issued_at =
            OffsetDateTime::parse(&payload.iat, &Rfc3339).map_err(|e| TokenError::Invalid(e.to_string()))?;
        let expires_at =
            OffsetDateTime::parse(&payload.exp, &Rfc3339).map_err(|e| TokenError::Invalid(e.to_string()))?;

        if expires_at <= OffsetDateTime::now_utc() {
            return Err(TokenError::Invalid("token is expired".into()));
        }

        let audience = payload.aud.unwrap_or_default();
        let scope = payload.scope.unwrap_or_default();
        let issuer = payload.iss.unwrap_or_default();
        let organization_id = payload
            .org_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|e| TokenError::Invalid(e.to_string()))?;

        Ok(AccessTokenClaims {
            account_id,
            session_id,
            token_id,
            issued_at,
            expires_at,
            audience,
            scope,
            organization_id,
            issuer,
        })
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
