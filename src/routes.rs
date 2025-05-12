mod index;
mod v1;
use crate::app_state::AppState;
use axum::{http::header, Router};
use tower_http::cors::{Any, CorsLayer};

pub fn create_routes() -> Router<AppState> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([header::ACCEPT, header::AUTHORIZATION, header::CONTENT_TYPE]);

    Router::new()
        .merge(index::index_route())
        .nest("/api/v1", v1::v1_routes())
        .layer(cors)
}
