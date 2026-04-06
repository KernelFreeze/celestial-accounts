use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Object;

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
    type Rejection = std::convert::Infallible;

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
