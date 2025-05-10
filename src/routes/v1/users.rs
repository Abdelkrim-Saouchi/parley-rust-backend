use crate::app_state::AppState;
use crate::handlers::v1::get_all_users;
use axum::{routing::get, Router};

pub fn users_routes() -> Router<AppState> {
    Router::new().route("/all", get(get_all_users::get_all_users))
}
