use crate::state::AppState;

pub mod auth;
pub mod oauth;

pub type Router = axum::Router<AppState>;

pub fn router() -> Router {
    Router::new()
        .nest("/auth", auth::router())
        .nest("/oauth", oauth::router())
}
