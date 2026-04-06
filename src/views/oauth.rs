use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum_reject_macro::HttpError;
use diesel_async::AsyncPgConnection;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::database::controllers::refresh_token;
use crate::extractors::DatabaseConnection;
use crate::state::AppState;
use crate::views::Router;

const ACCESS_TOKEN_HINT: &str = "access_token";
const REFRESH_TOKEN_HINT: &str = "refresh_token";

#[derive(Debug, Deserialize)]
struct RevokeTokenRequest {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Error, HttpError)]
enum RevokeError {
    #[http_error(status = INTERNAL_SERVER_ERROR, message = "internal_error")]
    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[http_error(status = INTERNAL_SERVER_ERROR, message = "internal_error")]
    #[error("token revocation store error: {0}")]
    RevocationStore(#[from] crate::auth::revocation::RevocationError),
}

pub fn router() -> Router {
    Router::new().route("/revoke", post(revoke_handler))
}

async fn revoke_handler(
    State(state): State<AppState>, DatabaseConnection(mut conn): DatabaseConnection,
    Form(request): Form<RevokeTokenRequest>,
) -> Result<StatusCode, RevokeError> {
    let token = request.token.trim();
    if token.is_empty() {
        return Ok(StatusCode::OK);
    }

    match request.token_type_hint.as_deref() {
        Some(REFRESH_TOKEN_HINT) => {
            let _ = revoke_refresh_token(&mut conn, token).await?;
        },
        Some(ACCESS_TOKEN_HINT) => {
            let _ = revoke_access_token(&state, token).await?;
        },
        _ => {
            // Best-effort fallback when hint is absent/invalid:
            // try refresh token first, then access token.
            if !revoke_refresh_token(&mut conn, token).await? {
                let _ = revoke_access_token(&state, token).await?;
            }
        },
    }

    // OAuth revocation returns 200 even for unknown/invalid tokens.
    Ok(StatusCode::OK)
}

async fn revoke_refresh_token(conn: &mut AsyncPgConnection, token: &str) -> Result<bool, RevokeError> {
    let Some(raw_refresh) = parse_refresh_token(token) else {
        return Ok(false);
    };

    let refresh_hash = Sha256::digest(raw_refresh);
    let revoked_rows = refresh_token::revoke_by_hash(conn, refresh_hash.as_slice()).await?;
    Ok(revoked_rows > 0)
}

async fn revoke_access_token(state: &AppState, token: &str) -> Result<bool, RevokeError> {
    let claims = match state.paseto_keys().verify_access_token(token) {
        Ok(claims) => claims,
        Err(_) => return Ok(false),
    };

    state
        .token_revocation_store()
        .revoke_jti_until(claims.token_id, claims.expires_at)
        .await?;

    Ok(true)
}

fn parse_refresh_token(token: &str) -> Option<Vec<u8>> {
    let raw = hex::decode(token).ok()?;
    if raw.len() != 32 {
        return None;
    }
    Some(raw)
}
