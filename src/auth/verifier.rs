use diesel_async::AsyncPgConnection;
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;

use crate::auth::password::PasswordVerifier;
use crate::database::controllers::{account, credential};
use crate::database::models::{Account, Credential, CredentialKind};

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("invalid_credentials")]
    InvalidCredentials,

    #[error("internal error during verification")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Trait for pluggable credential verification schemes.
///
/// Each implementation handles a specific `CredentialKind` (password, webauthn,
/// etc.). The associated `Payload` type carries the request-specific data
/// needed for verification.
///
/// Implementations must guarantee constant-time behavior with respect to
/// success/failure to prevent timing-based user enumeration.
pub trait CredentialVerifier: Send + Sync {
    /// The request-specific data this verifier needs (e.g., plaintext
    /// password).
    type Payload: Send + ?Sized;

    /// Verify a credential against the given payload.
    async fn verify(&self, credential: &Credential, payload: &Self::Payload) -> Result<(), VerificationError>;

    /// Perform a dummy verification that takes roughly the same wall-clock time
    /// as a real one. Called when the account or credential doesn't exist,
    /// to equalize response timing.
    async fn dummy_verify(&self);
}

/// The login request body. Serde's internally-tagged representation routes to
/// the correct variant based on the `kind` field.
///
/// ```json
/// {"kind": "password", "username": "alice", "password": "correct-horse-battery-staple"}
/// ```
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginRequest {
    Password { username: String, password: String },
}

/// Authenticate a user against the database using the appropriate credential
/// verifier.
///
/// Every code path performs the same cryptographic work to prevent timing-based
/// enumeration.
pub async fn authenticate(
    conn: &mut AsyncPgConnection, request: &LoginRequest, password_verifier: &PasswordVerifier,
) -> Result<Account, VerificationError> {
    match request {
        LoginRequest::Password { username, password } => {
            authenticate_password(conn, username, password, password_verifier).await
        },
    }
}

async fn authenticate_password(
    conn: &mut AsyncPgConnection, username: &str, password: &str, verifier: &PasswordVerifier,
) -> Result<Account, VerificationError> {
    let account = match account::find_by_username(conn, username).await {
        Ok(account) => account,
        Err(_) => {
            verifier.dummy_verify().await;
            return Err(VerificationError::InvalidCredentials);
        },
    };

    if let Some(locked_until) = account.locked_until
        && locked_until > OffsetDateTime::now_utc()
    {
        verifier.dummy_verify().await;
        return Err(VerificationError::InvalidCredentials);
    }

    let credential = match credential::find_by_account_and_kind(conn, account.id, CredentialKind::Password).await {
        Ok(cred) => cred,
        Err(_) => {
            verifier.dummy_verify().await;
            return Err(VerificationError::InvalidCredentials);
        },
    };

    verifier.verify(&credential, password).await?;

    Ok(account)
}
