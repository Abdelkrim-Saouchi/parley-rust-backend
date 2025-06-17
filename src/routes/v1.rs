pub mod chats;
pub mod friends;
pub mod users;
pub mod websocket;
use crate::app_state::AppState;
use axum::Router;

pub fn v1_routes() -> Router<AppState> {
    Router::new()
        .nest("/users", users::users_routes()) // /api/v1/users
        .nest("/friends", friends::friends_routes()) // /api/v1/friends
        .nest("/chats", chats::chats_routes()) // /api/v1/chats
        .nest("/", websocket::websocket_routes()) // ws endpoint /api/v1/ws
}
