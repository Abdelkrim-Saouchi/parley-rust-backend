use crate::app_state::AppState;
use crate::handlers::v1::{email_auth, get_all_users, oauth};
use axum::{routing::get, routing::post, Router};

pub fn users_routes() -> Router<AppState> {
    Router::new()
        .route("/all", get(get_all_users::get_all_users))
        .route("/signup", post(email_auth::signup)) // /api/v1/users/signup
        .route("/login", post(email_auth::login)) // /api/v1/users/login
        .route("/logout", post(email_auth::logout)) // /api/v1/users/logout
        .route(
            "/verify/{user_id}/{token}",
            get(email_auth::verify_email_handler),
        )
        .route("/me", get(email_auth::get_authenticated_user_id)) // /api/v1/users/me
        // Oauth routes
        .route("/auth/{provider}/login", get(oauth::oauth_login_handler))
        .route(
            "/auth/{provider}/callback",
            get(oauth::oauth_callback_handler),
        )
        .route("/auth/{provider}/logout", get(oauth::oauth_logout_handler))
}
