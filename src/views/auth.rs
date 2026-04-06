use axum::Json;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_reject_macro::HttpError;
use serde::Serialize;
use thiserror::Error;
use time::Duration;

use crate::auth::TokenType;
use crate::auth::session::{self, SessionError, SessionTokens};
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

pub(super) enum LoginResponse {
    Authenticated(SessionTokens),
    MfaRequired {
        mfa_token: String,
        mfa_expires_in: Duration,
    },
}

#[derive(Serialize)]
struct AuthenticatedBody {
    access_token: String,
    token_type: TokenType,
    expires_in: Duration,
}

#[derive(Serialize)]
struct MfaRequiredBody {
    mfa_token: String,
    mfa_expires_in: Duration,
}

/// Build the refresh token cookie.
///
/// Per the architecture doc (section 5): `Secure`, `HttpOnly`,
/// `SameSite=Lax`, `Path=/oauth/token`, no explicit `Domain`.
fn refresh_token_cookie(value: String) -> Cookie<'static> {
    Cookie::build(("refresh_token", value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/oauth/token")
        .max_age(session::REFRESH_TOKEN_LIFETIME)
        .build()
}

impl IntoResponse for LoginResponse {
    fn into_response(self) -> Response {
        match self {
            Self::Authenticated(tokens) => {
                let jar = axum_extra::extract::CookieJar::new().add(refresh_token_cookie(tokens.refresh_token));
                let body = AuthenticatedBody {
                    access_token: tokens.access_token,
                    token_type: tokens.token_type,
                    expires_in: tokens.expires_in,
                };
                (jar, Json(body)).into_response()
            },
            Self::MfaRequired {
                mfa_token,
                mfa_expires_in,
            } => Json(MfaRequiredBody {
                mfa_token,
                mfa_expires_in,
            })
            .into_response(),
        }
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/login", post(login::handler))
        .route("/mfa/verify", post(mfa_verify::handler))
}
