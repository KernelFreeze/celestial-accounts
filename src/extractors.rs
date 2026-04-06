use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::Deref;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::{AUTHORIZATION, USER_AGENT, WWW_AUTHENTICATE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use diesel::result::Error as DieselError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Object;
use time::OffsetDateTime;

use crate::auth::token::AccessTokenClaims;
use crate::database::controllers::account;
use crate::database::models::Account;
use crate::state::AppState;

pub struct DatabaseConnection(pub Object<AsyncPgConnection>);

#[derive(Debug)]
pub struct DatabaseConnectionRejection;

impl IntoResponse for DatabaseConnectionRejection {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}

impl FromRequestParts<AppState> for DatabaseConnection {
    type Rejection = DatabaseConnectionRejection;

    async fn from_request_parts(_parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let conn = state.database().get().await.map_err(|_| DatabaseConnectionRejection)?;
        Ok(DatabaseConnection(conn))
    }
}

/// Client IP address and User-Agent extracted from the request.
///
/// The IP is resolved from the `X-Forwarded-For` header (first entry) when
/// present, falling back to the peer socket address. User-Agent comes straight
/// from the header.
pub struct ClientInfo {
    pub ip: String,
    pub user_agent: String,
}

impl FromRequestParts<AppState> for ClientInfo {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let connect_info = ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await.ok();
        let ip = client_ip(&parts.headers, &connect_info);
        let user_agent = parts
            .headers
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        Ok(ClientInfo { ip, user_agent })
    }
}

/// Resolve the client IP, preferring `X-Forwarded-For` over the socket address.
fn client_ip(headers: &HeaderMap, connect_info: &Option<ConnectInfo<SocketAddr>>) -> String {
    if let Some(forwarded_for) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded_for.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }

    connect_info
        .as_ref()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_default()
}

/// Authenticated principal resolved from an access token.
#[derive(Debug)]
pub struct AuthenticatedPrincipal {
    pub account: Account,
    pub claims: AccessTokenClaims,
    pub access_token: String,
}

/// Tuple-style auth extractor so handlers can write:
/// `AuthenticatedUser(user): AuthenticatedUser`
pub struct AuthenticatedUser(pub AuthenticatedPrincipal);

impl AuthenticatedUser {
    pub fn account(&self) -> &Account {
        &self.0.account
    }

    pub fn claims(&self) -> &AccessTokenClaims {
        &self.0.claims
    }

    pub fn access_token(&self) -> &str {
        &self.0.access_token
    }

    pub fn has_scope(&self, required_scope: &str) -> bool {
        self.0.claims.has_scope(required_scope)
    }

    pub fn has_any_scope<'a, I>(&self, required_scopes: I) -> bool
    where
        I: IntoIterator<Item = &'a str>, {
        self.0.claims.has_any_scope(required_scopes)
    }

    pub fn has_all_scopes<'a, I>(&self, required_scopes: I) -> bool
    where
        I: IntoIterator<Item = &'a str>, {
        self.0.claims.has_all_scopes(required_scopes)
    }
}

impl Deref for AuthenticatedUser {
    type Target = Account;

    fn deref(&self) -> &Self::Target {
        &self.0.account
    }
}

#[derive(Debug)]
pub enum AuthExtractorRejection {
    Unauthorized(&'static str),
    Forbidden(&'static str),
    InternalServerError,
}

impl AuthExtractorRejection {
    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn body(&self) -> &'static str {
        match self {
            Self::Unauthorized(code) | Self::Forbidden(code) => code,
            Self::InternalServerError => "internal_error",
        }
    }

    fn www_authenticate(&self) -> Option<HeaderValue> {
        match self {
            Self::Unauthorized(_) => Some(HeaderValue::from_static(r#"Bearer error="invalid_token""#)),
            Self::Forbidden(_) => Some(HeaderValue::from_static(r#"Bearer error="insufficient_scope""#)),
            Self::InternalServerError => None,
        }
    }
}

impl IntoResponse for AuthExtractorRejection {
    fn into_response(self) -> Response {
        let mut response = (self.status(), self.body()).into_response();
        if let Some(value) = self.www_authenticate() {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        response
    }
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AuthExtractorRejection;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let authorization = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthExtractorRejection::Unauthorized("missing_authorization_header"))?;

        let token = bearer_token_from_header(authorization)
            .ok_or(AuthExtractorRejection::Unauthorized("invalid_authorization_header"))?;

        let claims = state
            .paseto_keys()
            .verify_access_token(token)
            .map_err(|_| AuthExtractorRejection::Unauthorized("invalid_access_token"))?;

        let revoked = state
            .token_revocation_store()
            .is_jti_revoked(claims.token_id)
            .await
            .map_err(|_| AuthExtractorRejection::InternalServerError)?;
        if revoked {
            return Err(AuthExtractorRejection::Unauthorized("token_revoked"));
        }

        let mut conn = state
            .database()
            .get()
            .await
            .map_err(|_| AuthExtractorRejection::InternalServerError)?;

        let account = account::find_by_id(&mut conn, claims.account_id)
            .await
            .map_err(|err| match err {
                DieselError::NotFound => AuthExtractorRejection::Unauthorized("account_not_found"),
                _ => AuthExtractorRejection::InternalServerError,
            })?;

        if account
            .locked_until
            .map(|until| until > OffsetDateTime::now_utc())
            .unwrap_or(false)
        {
            return Err(AuthExtractorRejection::Unauthorized("account_locked"));
        }

        Ok(Self(AuthenticatedPrincipal {
            account,
            claims,
            access_token: token.to_owned(),
        }))
    }
}

fn bearer_token_from_header(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    Some(token)
}

/// Compile-time marker trait for required scopes.
pub trait RequiredScope {
    const SCOPE: &'static str;
}

/// Scope-checking extractor that enforces `S::SCOPE`.
///
/// Usage:
/// - define a marker type implementing `RequiredScope`
/// - extract `Scoped<YourMarker>` in handlers
///
/// Example marker:
/// `struct ReadProfile;`
/// `impl RequiredScope for ReadProfile { const SCOPE: &'static str =
/// "profile:read"; }`
pub struct Scoped<S: RequiredScope>(pub AuthenticatedUser, PhantomData<S>);

impl<S: RequiredScope> Scoped<S> {
    pub fn into_user(self) -> AuthenticatedUser {
        self.0
    }
}

impl<S: RequiredScope> Deref for Scoped<S> {
    type Target = AuthenticatedUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: RequiredScope> FromRequestParts<AppState> for Scoped<S> {
    type Rejection = AuthExtractorRejection;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;

        if !user.has_scope(S::SCOPE) {
            return Err(AuthExtractorRejection::Forbidden("insufficient_scope"));
        }

        Ok(Self(user, PhantomData))
    }
}
