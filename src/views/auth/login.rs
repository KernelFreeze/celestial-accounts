use axum::Json;
use axum::extract::State;

use super::{LoginError, LoginResponse};
use crate::auth::session;
use crate::auth::verifier::{LoginRequest, authenticate};
use crate::extractors::DatabaseConnection;
use crate::state::AppState;

pub(super) async fn handler(
    State(state): State<AppState>, DatabaseConnection(mut conn): DatabaseConnection, Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, LoginError> {
    let account = authenticate(&mut conn, &request, state.password_verifier()).await?;

    if account.mfa_enforced {
        let partial_token = state
            .paseto_keys()
            .issue_partial_token(account.id, session::PARTIAL_TOKEN_LIFETIME)?;
        return Ok(Json(LoginResponse::MfaRequired {
            mfa_token: partial_token,
            mfa_expires_in: session::PARTIAL_TOKEN_LIFETIME,
        }));
    }

    let tokens = session::create_full_session(&mut conn, state.paseto_keys(), account.id, "", "").await?;

    Ok(Json(LoginResponse::Authenticated {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
    }))
}
