use diesel_async::AsyncPgConnection;
use rand::RngExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::TokenType;
use crate::auth::token::{PasetoKeys, TokenError};
use crate::database::controllers::{refresh_token, session};
use crate::database::models::{NewRefreshToken, NewSession};

/// Well-known client ID for direct-login sessions (seeded by migration).
const FIRST_PARTY_CLIENT_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);

pub const ACCESS_TOKEN_LIFETIME: Duration = Duration::minutes(15);
pub const PARTIAL_TOKEN_LIFETIME: Duration = Duration::minutes(2);
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(90);
const SESSION_LIFETIME: Duration = Duration::days(30);

#[derive(Debug, Serialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: TokenType,
    pub expires_in: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("token error: {0}")]
    Token(#[from] TokenError),

    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),
}

/// Create a full authenticated session: inserts a session row, issues a
/// v4.public access token, and stores a hashed refresh token.
pub async fn create_full_session(
    conn: &mut AsyncPgConnection, keys: &PasetoKeys, account_id: Uuid, ip_address: &str, user_agent: &str,
) -> Result<SessionTokens, SessionError> {
    let now = OffsetDateTime::now_utc();
    let session_id = Uuid::now_v7();

    // Persist the session record.
    let new_session = NewSession {
        id: session_id,
        account_id,
        ip_address,
        user_agent,
        expires_at: now + SESSION_LIFETIME,
    };
    session::create(conn, &new_session).await?;

    // Issue the PASETO v4.public access token.
    let access_token = keys.issue_access_token(account_id, session_id, ACCESS_TOKEN_LIFETIME)?;

    // Generate an opaque refresh token, store its SHA-256 hash.
    let mut raw_refresh = [0u8; 32];
    rand::rng().fill(&mut raw_refresh);
    let refresh_hex = hex::encode(raw_refresh);
    let refresh_hash = Sha256::digest(raw_refresh);

    let new_refresh = NewRefreshToken {
        token_hash: refresh_hash.as_slice(),
        client_id: FIRST_PARTY_CLIENT_ID,
        account_id,
        scope: "*",
        expires_at: now + REFRESH_TOKEN_LIFETIME,
        rotated_from: None,
    };
    refresh_token::create(conn, &new_refresh).await?;

    Ok(SessionTokens {
        access_token,
        refresh_token: refresh_hex,
        token_type: TokenType::Bearer,
        expires_in: ACCESS_TOKEN_LIFETIME,
    })
}
