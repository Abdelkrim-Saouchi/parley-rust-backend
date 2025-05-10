use axum::response::IntoResponse;

pub fn hello_v1() -> impl IntoResponse {
    "hello from v1"
}
