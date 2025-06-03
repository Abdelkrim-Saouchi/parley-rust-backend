use crate::app_state::AppState;
use crate::handlers::v1::{email_auth, get_all_users, oauth, profile};
use crate::middlewares::auth::auth_middleware;
use axum::middleware;
use axum::{routing::get, routing::post, Router};

pub fn users_routes() -> Router<AppState> {
    // Public routes that don't require authentication
    let public_routes = Router::new()
        .route("/signup", post(email_auth::signup))
        .route("/login", post(email_auth::login))
        .route("/logout", post(email_auth::logout))
        .route(
            "/verify/{user_id}/{token}",
            get(email_auth::verify_email_handler),
        )
        .route(
            "/resend-verification",
            post(email_auth::resend_verification_email_hander),
        )
        .route(
            "/forgot-password",
            post(email_auth::forgot_password_handler),
        )
        .route(
            "/reset-password/{user_id}/{token}",
            post(email_auth::reset_password_handler),
        )
        // OAuth routes
        .route("/auth/{provider}/login", get(oauth::oauth_login_handler))
        .route(
            "/auth/{provider}/callback",
            get(oauth::oauth_callback_handler),
        )
        .route("/auth/{provider}/logout", get(oauth::oauth_logout_handler))
        // test routes
        .route("/all", get(get_all_users::get_all_users));

    // Protected routes that require authentication
    let protected_routes = Router::new()
        .route("/me", get(email_auth::get_authenticated_user_id))
        .route("/profile/{user_id}", get(profile::get_profile))
        .route("/profile/update/{user_id}", post(profile::update_profile))
        .layer(middleware::from_fn(auth_middleware));

    // Merge public and protected routes
    Router::new().merge(public_routes).merge(protected_routes)
}
