use crate::app_state::AppState;
use crate::handlers::hello::hello;
use axum::{routing::get, Router};

pub fn index_route() -> Router<AppState> {
    Router::new().route("/", get(hello))
}
