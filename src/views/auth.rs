use axum::routing::post;
use axum_reject_macro::HttpError;
use serde::Serialize;
use thiserror::Error;
use time::Duration;

use crate::auth::TokenType;
use crate::auth::session::SessionError;
use crate::auth::token::TokenError;
use crate::auth::verifier::VerificationError;
use crate::views::Router;

mod login;
mod mfa_verify;

#[derive(Debug, Error, HttpError)]
pub(super) enum LoginError {
    #[http_error(status = UNAUTHORIZED, message = "invalid_credentials")]
    #[error(transparent)]
    InvalidCredentials(#[from] VerificationError),

    #[http_error(status = INTERNAL_SERVER_ERROR, message = "internal_error")]
    #[error("session creation failed: {0}")]
    Session(#[from] SessionError),

    #[http_error(status = INTERNAL_SERVER_ERROR, message = "internal_error")]
    #[error("token error: {0}")]
    Token(#[from] TokenError),
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum LoginResponse {
    Authenticated {
        access_token: String,
        refresh_token: String,
        token_type: TokenType,
        expires_in: Duration,
    },
    MfaRequired {
        mfa_token: String,
        mfa_expires_in: Duration,
    },
}

pub fn router() -> Router {
    Router::new()
        .route("/login", post(login::handler))
        .route("/mfa/verify", post(mfa_verify::handler))
}
