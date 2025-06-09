use crate::handlers::v1::friends;
use crate::{app_state::AppState, middlewares::auth::auth_middleware};
use axum::routing::post;
use axum::{middleware, Router};

pub fn friends_routes() -> Router<AppState> {
    // Protected routes that require authentication
    Router::new()
        .route("/send_friend_request", post(friends::send_friend_request))
        .route(
            "/accept_friend_request",
            post(friends::accept_friend_request),
        )
        .route(
            "/decline_friend_request",
            post(friends::decline_friend_request),
        )
        .layer(middleware::from_fn(auth_middleware))
}
