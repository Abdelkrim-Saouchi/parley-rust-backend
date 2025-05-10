pub mod users;
use crate::app_state::AppState;
use axum::Router;

pub fn v1_routes() -> Router<AppState> {
    Router::new().nest("/users", users::users_routes())
}
