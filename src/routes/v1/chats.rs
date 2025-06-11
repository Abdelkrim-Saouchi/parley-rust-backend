use crate::handlers::v1::chats;
use crate::{app_state::AppState, middlewares::auth::auth_middleware};
use axum::routing::post;
use axum::{middleware, Router};

pub fn chats_routes() -> Router<AppState> {
    // Protected routes that require authentication
    Router::new()
        .route("/create_direct_chat", post(chats::create_direct_chat))
        .route("/create_group_chat", post(chats::create_group_chat))
        .route("/send_group_invitation", post(chats::send_group_invitation))
        .route(
            "/accept_group_invitation",
            post(chats::accept_group_invitation),
        )
        .route(
            "/decline_group_invitation",
            post(chats::decline_group_invitation),
        )
        .layer(middleware::from_fn(auth_middleware))
}
