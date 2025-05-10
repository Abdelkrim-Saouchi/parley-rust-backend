mod index;
mod v1;
use crate::app_state::AppState;
use axum::Router;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .merge(index::index_route())
        .nest("/api/v1", v1::v1_routes())
}
