pub fn websocket_routes() -> axum::Router<crate::app_state::AppState> {
    axum::Router::new()
        .route(
            "/ws",
            axum::routing::get(crate::websocket::handlers::websocket_handler),
        )
        .layer(axum::middleware::from_fn(
            crate::middlewares::auth::auth_middleware,
        ))
}
