use crate::app_state::AppState;
use crate::handlers::v1::{email_auth, get_all_users};
use axum::{routing::get, routing::post, Router};

pub fn users_routes() -> Router<AppState> {
    Router::new()
        .route("/all", get(get_all_users::get_all_users))
        .route("/signup", post(email_auth::signup)) // /api/v1/users/signup
}
