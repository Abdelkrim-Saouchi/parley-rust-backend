use axum::response::IntoResponse;

pub async fn get_all_users() -> impl IntoResponse {
    "All users from V1 handler"
}
