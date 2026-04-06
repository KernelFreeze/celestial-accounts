use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use super::{LoginError, LoginResponse};
use crate::auth::session;
use crate::auth::verifier::CredentialVerifier;
use crate::database::controllers::credential;
use crate::database::models::CredentialKind;
use crate::extractors::{ClientInfo, DatabaseConnection};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(super) struct MfaVerifyRequest {
    mfa_token: String,
    code: String,
}

pub(super) async fn handler(
    State(state): State<AppState>, DatabaseConnection(mut conn): DatabaseConnection, client: ClientInfo,
    Json(request): Json<MfaVerifyRequest>,
) -> Result<LoginResponse, LoginError> {
    let claims = match state.paseto_keys().verify_partial_token(&request.mfa_token) {
        Ok(claims) => claims,
        Err(_) => {
            state.totp_verifier().dummy_verify().await;
            return Err(crate::auth::verifier::VerificationError::InvalidCredentials.into());
        },
    };

    let totp_credential =
        match credential::find_by_account_and_kind(&mut conn, claims.account_id, CredentialKind::Totp).await {
            Ok(cred) => cred,
            Err(_) => {
                state.totp_verifier().dummy_verify().await;
                return Err(crate::auth::verifier::VerificationError::InvalidCredentials.into());
            },
        };

    state.totp_verifier().verify(&totp_credential, &request.code).await?;

    let tokens = session::create_full_session(
        &mut conn,
        state.paseto_keys(),
        claims.account_id,
        &client.ip,
        &client.user_agent,
    )
    .await?;

    Ok(LoginResponse::Authenticated(tokens))
}
