use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
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
